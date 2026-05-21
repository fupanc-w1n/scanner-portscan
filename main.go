// Scanner-port: 端口扫描 Pod 主程序。
// 严格按架构 §5.2 / §7 / §9 实现。每个 host goroutine 内部有独立 rate.Limiter。
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	scannerconfig "scanner-port/internal/config"
	"scanner-port/internal/mysqldb"
	"scanner-port/internal/worker"
)

const dialTimeout = 2 * time.Second

func main() {
	cfg, err := scannerconfig.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Module != "portscan" {
		log.Fatalf("expect module=portscan, got %s", cfg.Module)
	}
	mc, err := cfg.ParsePortScan()
	if err != nil {
		log.Fatalf("parse module_config: %v", err)
	}
	if mc.QPS <= 0 {
		mc.QPS = 10
	}
	ports, err := parsePortList(mc.Ports)
	if err != nil {
		log.Fatalf("invalid ports: %v", err)
	}
	if len(ports) == 0 {
		log.Fatalf("empty port list")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr(),
		Password: envOr("DAST_REDIS_PASS", "redis"),
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("redis ping: %v", err)
	}
	defer rdb.Close()

	mdb, err := mysqldb.Open(cfg.MySQLAddr(), envOr("DAST_DB_USER", "root"), envOr("DAST_DB_PASS", "fupanC@123"), envOr("DAST_DB_NAME", "dast"))
	if err != nil {
		log.Fatalf("mysql open: %v", err)
	}
	defer mdb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("portscan: shutting down")
		cancel()
	}()

	w := worker.New(cfg, rdb, func(ctx context.Context, msg *worker.BusinessMessage, msgID string) worker.HandlerResult {
		return handlePort(ctx, cfg, mc, ports, mdb, msg)
	})
	if err := w.Run(ctx); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}

// handlePort 处理一条端口扫描消息:
//   - 并发对每个 host 扫描指定端口
//   - 写入开放端口结果
//   - 若开放 host 子集非空且 ConfigMap.workflow.downstreams.open_port 存在 -> 返回 DownstreamHosts.open_port
//   - 若开放 host 子集为空 -> 标记所有非 NULL 模块为 completed,标记分片完成
//   - 否则 -> 只标记 portscan_status=completed,检查分片完成
func handlePort(ctx context.Context, cfg *scannerconfig.Config, mc *scannerconfig.PortScanConfig, ports []int,
	mdb *mysqldb.DB, msg *worker.BusinessMessage) worker.HandlerResult {

	log.Printf("portscan task=%d part=%s hosts=%v", msg.TaskID, msg.TaskPartName, msg.Hosts)

	type hostScanResult struct {
		host string
		rows []mysqldb.PortResult
	}
	resultCh := make(chan hostScanResult, len(msg.Hosts))
	var wg sync.WaitGroup
	for _, h := range msg.Hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			resultCh <- hostScanResult{host: host, rows: scanHost(ctx, cfg.PolicyID, msg.TaskID, msg.TaskPartName, host, ports, mc.QPS)}
		}(h)
	}
	go func() { wg.Wait(); close(resultCh) }()

	openByHost := map[string]struct{}{}
	rows := make([]mysqldb.PortResult, 0, 64)
	for result := range resultCh {
		if len(result.rows) > 0 {
			openByHost[result.host] = struct{}{}
			rows = append(rows, result.rows...)
		}
	}
	if err := ctx.Err(); err != nil {
		return worker.HandlerResult{Err: err}
	}
	if err := mdb.DeletePortResultsForHosts(ctx, msg.TaskID, msg.TaskPartName, msg.Hosts); err != nil {
		return worker.HandlerResult{Err: fmt.Errorf("delete old ports: %w", err)}
	}
	if err := mdb.InsertPortResults(ctx, rows); err != nil {
		return worker.HandlerResult{Err: fmt.Errorf("insert ports: %w", err)}
	}

	// 任务终止检查
	term, err := mdb.IsTaskTerminated(ctx, msg.TaskID)
	if err != nil {
		return worker.HandlerResult{Err: fmt.Errorf("check task terminated: %w", err)}
	}
	if term {
		if err := mdb.SetPortScanCompleted(ctx, msg.TaskID, msg.TaskPartName); err != nil {
			return worker.HandlerResult{Err: err}
		}
		if _, err := mdb.MarkPartCompletedIfAllDone(ctx, msg.TaskID, msg.TaskPartName); err != nil {
			return worker.HandlerResult{Err: err}
		}
		return worker.HandlerResult{}
	}

	openHosts := make([]string, 0, len(openByHost))
	for _, h := range msg.Hosts {
		if _, ok := openByHost[h]; ok {
			openHosts = append(openHosts, h)
		}
	}
	log.Printf("portscan task=%d part=%s scanned_hosts=%d open_hosts=%d result_rows=%d", msg.TaskID, msg.TaskPartName, len(msg.Hosts), len(openHosts), len(rows))
	recordTaskEvent(ctx, mdb, msg.TaskID, "portscan",
		fmt.Sprintf("portscan part completed: part=%s scanned_hosts=%d open_hosts=%d open_ports=%d", msg.TaskPartName, len(msg.Hosts), len(openHosts), len(rows)),
		map[string]interface{}{"task_part_name": msg.TaskPartName, "scanned_hosts": len(msg.Hosts), "open_hosts": len(openHosts), "open_ports": len(rows)})

	// 无开放 host:把所有非 NULL 模块字段标完成,然后检查分片完成,不投递下游
	if len(openHosts) == 0 {
		if err := mdb.CompleteAllNonNullStatuses(ctx, msg.TaskID, msg.TaskPartName); err != nil {
			return worker.HandlerResult{Err: err}
		}
		if _, err := mdb.MarkPartCompletedIfAllDone(ctx, msg.TaskID, msg.TaskPartName); err != nil {
			return worker.HandlerResult{Err: err}
		}
		return worker.HandlerResult{}
	}

	// 有开放 host
	if err := mdb.SetPortScanCompleted(ctx, msg.TaskID, msg.TaskPartName); err != nil {
		return worker.HandlerResult{Err: err}
	}

	out := worker.HandlerResult{DownstreamHosts: map[string][]string{}}
	if _, ok := cfg.Workflow.Downstreams["open_port"]; ok {
		if err := mdb.SetNmapStatus(ctx, msg.TaskID, msg.TaskPartName, "running"); err != nil {
			return worker.HandlerResult{Err: err}
		}
		out.DownstreamHosts["open_port"] = openHosts
		log.Printf("portscan task=%d part=%s downstream=open_port hosts=%d", msg.TaskID, msg.TaskPartName, len(openHosts))
	}
	if _, err := mdb.MarkPartCompletedIfAllDone(ctx, msg.TaskID, msg.TaskPartName); err != nil {
		return worker.HandlerResult{Err: err}
	}
	return out
}

func scanHost(ctx context.Context, policyID, taskID uint64, partName, host string, ports []int, qps int) []mysqldb.PortResult {
	limiter := rate.NewLimiter(rate.Limit(qps), qps)
	dialer := net.Dialer{Timeout: dialTimeout}
	rows := make([]mysqldb.PortResult, 0, 8)
	for _, p := range ports {
		if err := limiter.Wait(ctx); err != nil {
			return rows
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		_ = conn.Close()
		rows = append(rows, mysqldb.PortResult{
			TaskID:       taskID,
			PolicyID:     policyID,
			TaskPartName: partName,
			Host:         host,
			Port:         p,
		})
	}
	return rows
}

// parsePortList 解析 ["80", "20-25,8888", "1-65535"] 这类字段成端口数字列表(去重)
func parsePortList(in []string) ([]int, error) {
	seen := map[int]struct{}{}
	out := []int{}
	add := func(p int) {
		if p < 1 || p > 65535 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		for _, seg := range strings.Split(raw, ",") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			if strings.Contains(seg, "-") {
				parts := strings.Split(seg, "-")
				if len(parts) != 2 {
					return nil, fmt.Errorf("bad range: %s", seg)
				}
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 != nil || err2 != nil || lo > hi {
					return nil, fmt.Errorf("bad range: %s", seg)
				}
				for i := lo; i <= hi; i++ {
					add(i)
				}
			} else {
				n, err := strconv.Atoi(seg)
				if err != nil {
					return nil, fmt.Errorf("bad port: %s", seg)
				}
				add(n)
			}
		}
	}
	return out, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func recordTaskEvent(ctx context.Context, mdb *mysqldb.DB, taskID uint64, module, message string, meta map[string]interface{}) {
	if err := mdb.InsertTaskEvent(ctx, taskID, "info", module, message, meta); err != nil {
		log.Printf("%s task=%d event insert err=%v", module, taskID, err)
	}
}
