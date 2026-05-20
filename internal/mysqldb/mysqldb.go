// Package mysqldb 提供 Worker 写结果表的最小封装。
// 不引入 GORM,直接使用 database/sql,把模块依赖控制到最小。
package mysqldb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// DB 简单包装
type DB struct {
	conn *sql.DB
}

// Open 建立连接
func Open(addr, user, pass, name string) (*DB, error) {
	tz := localTimezone()
	if loc, err := time.LoadLocation(tz); err == nil {
		time.Local = loc
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=true&loc=%s",
		user, pass, addr, name, url.QueryEscape(tz))
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}
	return &DB{conn: db}, nil
}

func localTimezone() string {
	if v := os.Getenv("TZ"); v != "" {
		return v
	}
	if v := os.Getenv("DAST_TIMEZONE"); v != "" {
		return v
	}
	return "Asia/Shanghai"
}

// Close 关闭
func (d *DB) Close() error { return d.conn.Close() }

// SQL 暴露底层 *sql.DB 供需要复杂查询的模块使用
func (d *DB) SQL() *sql.DB { return d.conn }

// PortResult 写入开放端口结果
type PortResult struct {
	TaskID       uint64
	PolicyID     uint64
	TaskPartName string
	Host         string
	Port         int
}

// InsertPortResults 批量写入开放端口
func (d *DB) InsertPortResults(ctx context.Context, rows []PortResult) error {
	if len(rows) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("INSERT INTO port_results(task_id,policy_id,task_part_name,host,port,protocol,state,created_at) VALUES ")
	args := make([]interface{}, 0, len(rows)*8)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?)")
		args = append(args, r.TaskID, r.PolicyID, r.TaskPartName, r.Host, r.Port, "tcp", "open", time.Now())
	}
	_, err := d.conn.ExecContext(ctx, sb.String(), args...)
	return err
}

// DeletePortResultsForHosts 删除当前分片当前 host 子集的旧端口结果。
// Worker 消息如果因为下游投递失败或 ACK 失败进入 PEL 重试,这里保证端口结果展示幂等。
func (d *DB) DeletePortResultsForHosts(ctx context.Context, taskID uint64, partName string, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}
	q := "DELETE FROM port_results WHERE task_id = ? AND task_part_name = ? AND host IN ("
	args := []interface{}{taskID, partName}
	for i, host := range hosts {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, host)
	}
	q += ")"
	_, err := d.conn.ExecContext(ctx, q, args...)
	return err
}

// ServiceResult nmap 服务识别写入
type ServiceResult struct {
	TaskID       uint64
	TaskPartName string
	Host         string
	Port         int
	Service      string
	Product      string
	Version      string
	RouteTo      string
}

// InsertServiceResults 批量写入服务识别
func (d *DB) InsertServiceResults(ctx context.Context, rows []ServiceResult) error {
	if len(rows) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("INSERT INTO service_results(task_id,task_part_name,host,port,protocol,state,service,product,version,route_to,created_at) VALUES ")
	args := make([]interface{}, 0, len(rows)*11)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?)")
		args = append(args, r.TaskID, r.TaskPartName, r.Host, r.Port, "tcp", "open", r.Service, r.Product, r.Version, r.RouteTo, time.Now())
	}
	_, err := d.conn.ExecContext(ctx, sb.String(), args...)
	return err
}

// Vulnerability 漏洞写入
type Vulnerability struct {
	TaskID       uint64
	TaskPartName string
	Host         string
	Port         int
	Matched      string
	TemplateID   string
	Name         string
	Severity     string
	Tags         string
	Request      string
	Response     string
	RawEventJSON string
}

// InsertVulnerability 单条漏洞写入
func (d *DB) InsertVulnerability(ctx context.Context, v Vulnerability) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO vulnerabilities(task_id,task_part_name,host,port,matched,template_id,name,severity,tags,request,response,raw_event_json,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.TaskID, v.TaskPartName, v.Host, v.Port, v.Matched, v.TemplateID, v.Name, v.Severity, v.Tags, v.Request, v.Response, v.RawEventJSON, time.Now())
	return err
}

// WeakPassFinding 弱口令命中
type WeakPassFinding struct {
	TaskID       uint64
	TaskPartName string
	Host         string
	Port         int
	Service      string
	Username     string
	Password     string
}

// InsertWeakPassFinding 单条写入
func (d *DB) InsertWeakPassFinding(ctx context.Context, f WeakPassFinding) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO weak_password_findings(task_id,task_part_name,host,port,service,username,password,created_at)
         VALUES(?,?,?,?,?,?,?,?)`,
		f.TaskID, f.TaskPartName, f.Host, f.Port, f.Service, f.Username, f.Password, time.Now())
	return err
}

// OpenPortRow 查询开放端口
type OpenPortRow struct {
	Host string
	Port int
}

// QueryOpenPorts 按 task_id + task_part_name + hosts 查询开放端口(服务识别 Pod 使用)
func (d *DB) QueryOpenPorts(ctx context.Context, taskID uint64, partName string, hosts []string) ([]OpenPortRow, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	q, args := buildHostIn("SELECT host, port FROM port_results WHERE task_id = ?", taskID, partName, hosts)
	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]OpenPortRow, 0)
	for rows.Next() {
		var r OpenPortRow
		if err := rows.Scan(&r.Host, &r.Port); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ServiceTarget 查询服务识别结果
type ServiceTarget struct {
	Host    string
	Port    int
	Service string
}

// QueryServiceTargets 下游模块查询当前批次 host 的服务目标
//
// services 过滤(空表示不过滤)
func (d *DB) QueryServiceTargets(ctx context.Context, taskID uint64, partName string, hosts, services []string) ([]ServiceTarget, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	base := "SELECT host, port, service FROM service_results WHERE task_id = ?"
	q, args := buildHostIn(base, taskID, partName, hosts)
	if len(services) > 0 {
		q += " AND service IN ("
		for i, s := range services {
			if i > 0 {
				q += ","
			}
			q += "?"
			args = append(args, s)
		}
		q += ")"
	}
	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ServiceTarget, 0)
	for rows.Next() {
		var r ServiceTarget
		if err := rows.Scan(&r.Host, &r.Port, &r.Service); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func buildHostIn(base string, taskID uint64, partName string, hosts []string) (string, []interface{}) {
	q := base + " AND task_part_name = ? AND host IN ("
	args := []interface{}{taskID, partName}
	for i, h := range hosts {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, h)
	}
	q += ")"
	return q, args
}

// ============ task_parts_progress 状态更新 ============

// SetPortScanCompleted portscan_status -> completed
func (d *DB) SetPortScanCompleted(ctx context.Context, taskID uint64, partName string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE task_parts_progress SET portscan_status='completed', updated_at=? WHERE task_id=? AND task_part_name=?`,
		time.Now(), taskID, partName)
	return err
}

// SetNmapStatus 设置 nmap_status
func (d *DB) SetNmapStatus(ctx context.Context, taskID uint64, partName, status string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE task_parts_progress SET nmap_status=?, updated_at=? WHERE task_id=? AND task_part_name=?`,
		status, time.Now(), taskID, partName)
	return err
}

// SetNucleiStatus 设置 nuclei_status
func (d *DB) SetNucleiStatus(ctx context.Context, taskID uint64, partName, status string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE task_parts_progress SET nuclei_status=?, updated_at=? WHERE task_id=? AND task_part_name=?`,
		status, time.Now(), taskID, partName)
	return err
}

// SetWeakPassStatus 设置 weakpass_status
func (d *DB) SetWeakPassStatus(ctx context.Context, taskID uint64, partName, status string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE task_parts_progress SET weakpass_status=?, updated_at=? WHERE task_id=? AND task_part_name=?`,
		status, time.Now(), taskID, partName)
	return err
}

// CompleteAllNonNullStatuses 端口扫描发现没有开放端口时,把所有非 NULL 模块字段标记 completed。
func (d *DB) CompleteAllNonNullStatuses(ctx context.Context, taskID uint64, partName string) error {
	q := `UPDATE task_parts_progress SET
        portscan_status = IF(portscan_status IS NULL, NULL, 'completed'),
        nmap_status     = IF(nmap_status IS NULL, NULL, 'completed'),
        nuclei_status   = IF(nuclei_status IS NULL, NULL, 'completed'),
        weakpass_status = IF(weakpass_status IS NULL, NULL, 'completed'),
        updated_at = ?
        WHERE task_id = ? AND task_part_name = ?`
	_, err := d.conn.ExecContext(ctx, q, time.Now(), taskID, partName)
	return err
}

// MarkPartCompletedIfAllDone 若该分片所有非 NULL 模块均 completed,把 status 标记为 completed。
// 返回是否被标记。
func (d *DB) MarkPartCompletedIfAllDone(ctx context.Context, taskID uint64, partName string) (bool, error) {
	q := `UPDATE task_parts_progress
        SET status='completed', completed_at=?, updated_at=?
        WHERE task_id=? AND task_part_name=? AND status<>'completed'
        AND (portscan_status IS NULL OR portscan_status='completed')
        AND (nmap_status IS NULL OR nmap_status='completed')
        AND (nuclei_status IS NULL OR nuclei_status='completed')
        AND (weakpass_status IS NULL OR weakpass_status='completed')`
	now := time.Now()
	res, err := d.conn.ExecContext(ctx, q, now, now, taskID, partName)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		// 同时 try to mark task completed if all parts completed
		_ = d.MarkTaskCompletedIfAllDone(ctx, taskID)
	}
	return n > 0, nil
}

// MarkTaskCompletedIfAllDone 若任务所有 part status=completed,把 tasks.status 标为 completed。
func (d *DB) MarkTaskCompletedIfAllDone(ctx context.Context, taskID uint64) error {
	q := `UPDATE tasks SET status='completed', finished_at=?, updated_at=?
        WHERE id=? AND status NOT IN ('completed','terminated','failed')
        AND NOT EXISTS (
          SELECT 1 FROM task_parts_progress
          WHERE task_id=? AND status<>'completed'
        )`
	now := time.Now()
	_, err := d.conn.ExecContext(ctx, q, now, now, taskID, taskID)
	return err
}

// IsTaskTerminated 检查任务是否已被前端终止
func (d *DB) IsTaskTerminated(ctx context.Context, taskID uint64) (bool, error) {
	row := d.conn.QueryRowContext(ctx, `SELECT status FROM tasks WHERE id=?`, taskID)
	var s string
	if err := row.Scan(&s); err != nil {
		return false, err
	}
	return s == "terminated", nil
}
