// Package mysqldb contains only the MySQL operations used by scanner-port.
package mysqldb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	conn *sql.DB
}

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

func (d *DB) Close() error { return d.conn.Close() }

type PortResult struct {
	TaskID       uint64
	PolicyID     uint64
	TaskPartName string
	Host         string
	Port         int
}

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

func (d *DB) InsertTaskEvent(ctx context.Context, taskID uint64, level, module, message string, meta interface{}) error {
	metaJSON := ""
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		metaJSON = string(b)
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO task_events(task_id,level,module,message,meta_json,created_at) VALUES(?,?,?,?,?,?)`,
		taskID, level, module, message, metaJSON, time.Now())
	return err
}

func (d *DB) SetPortScanCompleted(ctx context.Context, taskID uint64, partName string) error {
	return d.setModuleStatus(ctx, taskID, partName, "portscan_status", "completed")
}

func (d *DB) SetNmapStatus(ctx context.Context, taskID uint64, partName, status string) error {
	return d.setModuleStatus(ctx, taskID, partName, "nmap_status", status)
}

func (d *DB) setModuleStatus(ctx context.Context, taskID uint64, partName, column, status string) error {
	now := time.Now()
	if status == "running" {
		q := fmt.Sprintf(`UPDATE task_parts_progress SET %s=?, updated_at=?
            WHERE task_id=? AND task_part_name=? AND %s IS NOT NULL AND %s<>'completed'`, column, column, column)
		_, err := d.conn.ExecContext(ctx, q, status, now, taskID, partName)
		return err
	}
	q := fmt.Sprintf(`UPDATE task_parts_progress SET %s=?, updated_at=?
        WHERE task_id=? AND task_part_name=? AND %s IS NOT NULL`, column, column)
	_, err := d.conn.ExecContext(ctx, q, status, now, taskID, partName)
	return err
}

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
	if err := d.MarkTaskCompletedIfAllDone(ctx, taskID); err != nil {
		return n > 0, err
	}
	return n > 0, nil
}

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
