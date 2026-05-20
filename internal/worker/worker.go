// Package worker 提供 Scanner Pod 共享的运行框架(架构 §9)。
// 主循环顺序:
//  1. PEL 中 idle 超阈值的消息:先 messageID 加锁 -> XCLAIM -> handler -> ACK -> 释放锁
//  2. 没有可处理 PEL 时再 XREADGROUP > 读新消息:加锁 -> handler -> ACK -> 释放锁
//
// 终止/暂停由 broadcast.State 维护;锁 key 派生 lock:stream:{stream}:message:{messageID}。
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"scanner-port/internal/broadcast"
	scannerconfig "scanner-port/internal/config"
)

// BusinessMessage 业务 Stream 消息固定字段(架构 §7)
type BusinessMessage struct {
	TaskID       uint64   `json:"task_id"`
	TaskPartName string   `json:"task_part_name"`
	Hosts        []string `json:"hosts"`
}

// HandlerResult Handler 返回结果。
//   - DownstreamHosts: 按下游 key 划分要投递的 host 子集(例如端口扫描返回 {"open_port": [...]} )
//   - Err: 处理失败,不 ACK,留待 PEL 恢复
type HandlerResult struct {
	DownstreamHosts map[string][]string
	Err             error
}

// Handler 业务处理函数。msg 是已解析的业务消息,cfg 是 ConfigMap 启动配置。
type Handler func(ctx context.Context, msg *BusinessMessage, msgID string) HandlerResult

// Worker 一个完整的 Scanner Pod 运行单元。Module 各 cmd/main 构造并 Run。
type Worker struct {
	Cfg          *scannerconfig.Config
	RDB          *redis.Client
	ConsumerName string
	Handler      Handler
	State        *broadcast.State

	// PEL 抢占的 idle 阈值,默认 cfg.Redis.PendingIdleSeconds
	PendingIdle time.Duration
	LockTTL     time.Duration
	LockRenew   time.Duration

	stopOnce sync.Once
}

// New 构造一个 Worker。
func New(cfg *scannerconfig.Config, rdb *redis.Client, h Handler) *Worker {
	consumer := fmt.Sprintf("%s-%s-%d-%d", cfg.Module, podHostname(), os.Getpid(), time.Now().UnixNano())
	return &Worker{
		Cfg:          cfg,
		RDB:          rdb,
		ConsumerName: consumer,
		Handler:      h,
		State:        broadcast.NewState(),
		PendingIdle:  time.Duration(cfg.Redis.PendingIdleSeconds) * time.Second,
		LockTTL:      time.Duration(cfg.Redis.LockTTLSeconds) * time.Second,
		LockRenew:    time.Duration(cfg.Redis.LockRenewSeconds) * time.Second,
	}
}

// Run 启动监听循环。ctx 取消后退出。
func (w *Worker) Run(ctx context.Context) error {
	if w.RDB == nil || w.Handler == nil || w.Cfg == nil {
		return errors.New("worker not properly initialized")
	}
	// 1) 业务 Stream Consumer Group
	if err := w.ensureGroup(ctx); err != nil {
		return err
	}
	// 2) 控制流广播监听
	broadcast.Start(ctx, w.RDB, w.Cfg.Redis.ControlStream, w.State)

	log.Printf("[%s] worker started, consumer=%s stream=%s group=%s", w.Cfg.Module, w.ConsumerName, w.Cfg.Redis.Stream, w.Cfg.Redis.Group)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if w.tryProcessPending(ctx) {
			continue
		}
		w.tryProcessNew(ctx)
	}
}

func (w *Worker) ensureGroup(ctx context.Context) error {
	err := w.RDB.XGroupCreateMkStream(ctx, w.Cfg.Redis.Stream, w.Cfg.Redis.Group, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return fmt.Errorf("xgroup create: %w", err)
	}
	return nil
}

// tryProcessPending PEL 恢复:遵循 §6.3 的严格顺序,先锁后 XCLAIM。
func (w *Worker) tryProcessPending(ctx context.Context) bool {
	pending, err := w.RDB.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: w.Cfg.Redis.Stream,
		Group:  w.Cfg.Redis.Group,
		Start:  "-",
		End:    "+",
		Count:  10,
	}).Result()
	if err != nil || len(pending) == 0 {
		return false
	}
	for _, p := range pending {
		if p.Idle < w.PendingIdle {
			continue
		}
		key := lockKey(w.Cfg.Redis.Stream, p.ID)
		ok, err := w.acquireLock(ctx, key)
		if err != nil || !ok {
			// 已被其他 Pod 锁定,跳过
			continue
		}
		msgs, err := w.RDB.XClaim(ctx, &redis.XClaimArgs{
			Stream:   w.Cfg.Redis.Stream,
			Group:    w.Cfg.Redis.Group,
			Consumer: w.ConsumerName,
			MinIdle:  w.PendingIdle,
			Messages: []string{p.ID},
		}).Result()
		if err != nil || len(msgs) == 0 {
			_ = w.releaseLock(ctx, key)
			continue
		}
		w.handleMessage(ctx, msgs[0], key)
		return true
	}
	return false
}

// tryProcessNew 读取新消息;每条消息独立加锁/处理/ACK。
func (w *Worker) tryProcessNew(ctx context.Context) {
	streams, err := w.RDB.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    w.Cfg.Redis.Group,
		Consumer: w.ConsumerName,
		Streams:  []string{w.Cfg.Redis.Stream, ">"},
		Count:    1,
		Block:    2 * time.Second,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return
		}
		time.Sleep(time.Second)
		return
	}
	if len(streams) == 0 || len(streams[0].Messages) == 0 {
		return
	}
	for _, m := range streams[0].Messages {
		key := lockKey(w.Cfg.Redis.Stream, m.ID)
		ok, err := w.acquireLock(ctx, key)
		if err != nil || !ok {
			// 加锁失败:跳过,不 ACK,等待 PEL 恢复
			continue
		}
		w.handleMessage(ctx, m, key)
	}
}

// handleMessage 处理单条业务消息。锁必须释放;成功路径 ACK,失败路径不 ACK。
func (w *Worker) handleMessage(ctx context.Context, m redis.XMessage, lockKey string) {
	defer func() { _ = w.releaseLock(ctx, lockKey) }()

	bm, err := parseBusiness(m)
	if err != nil {
		log.Printf("[%s] invalid message %s: %v", w.Cfg.Module, m.ID, err)
		// 视为非法消息,ACK 释放,避免无限重试
		w.ackMessage(ctx, m.ID, "invalid")
		return
	}

	// 暂停:释放锁,不 ACK,直接 continue
	if w.State.IsPaused(bm.TaskID) {
		log.Printf("[%s] task %d paused, skip msg %s", w.Cfg.Module, bm.TaskID, m.ID)
		return
	}
	// 终止:跳过扫描并 ACK
	if w.State.IsTerminated(bm.TaskID) {
		log.Printf("[%s] task %d terminated, skip+ack msg %s", w.Cfg.Module, bm.TaskID, m.ID)
		w.ackMessage(ctx, m.ID, "terminated-before-handler")
		return
	}

	// 锁续期 goroutine
	renewCtx, cancelRenew := context.WithCancel(ctx)
	defer cancelRenew()
	go w.renewLoop(renewCtx, lockKey)

	// 业务处理
	res := w.Handler(ctx, bm, m.ID)
	if res.Err != nil {
		log.Printf("[%s] handler error msg=%s: %v", w.Cfg.Module, m.ID, res.Err)
		return // 不 ACK,等待 PEL 重试
	}

	// 处理完后再检查终止状态:已终止则不投递下游
	if w.State.IsTerminated(bm.TaskID) {
		w.ackMessage(ctx, m.ID, "terminated-after-handler")
		return
	}

	// 投递下游:由 Handler 返回的 DownstreamHosts 决定;ConfigMap 中未声明对应下游则跳过。
	for key, hosts := range res.DownstreamHosts {
		if len(hosts) == 0 {
			continue
		}
		ds, ok := w.Cfg.Workflow.Downstreams[key]
		if !ok {
			continue
		}
		hostsJSON, _ := json.Marshal(hosts)
		if _, err := w.RDB.XAdd(ctx, &redis.XAddArgs{
			Stream: ds.Stream,
			Values: map[string]interface{}{
				"task_id":        bm.TaskID,
				"task_part_name": bm.TaskPartName,
				"hosts":          string(hostsJSON),
			},
		}).Result(); err != nil {
			log.Printf("[%s] xadd downstream %s err: %v", w.Cfg.Module, ds.Stream, err)
			return // 不 ACK,留待重试
		}
	}

	w.ackMessage(ctx, m.ID, "success")
}

func (w *Worker) ackMessage(ctx context.Context, msgID, reason string) {
	n, err := w.RDB.XAck(ctx, w.Cfg.Redis.Stream, w.Cfg.Redis.Group, msgID).Result()
	if err != nil {
		log.Printf("[%s] xack msg=%s reason=%s err=%v", w.Cfg.Module, msgID, reason, err)
		return
	}
	if n == 0 {
		log.Printf("[%s] xack msg=%s reason=%s acked=0 stream=%s group=%s", w.Cfg.Module, msgID, reason, w.Cfg.Redis.Stream, w.Cfg.Redis.Group)
	}
}

func (w *Worker) renewLoop(ctx context.Context, key string) {
	if w.LockRenew <= 0 {
		return
	}
	t := time.NewTicker(w.LockRenew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = w.renewLock(ctx, key)
		}
	}
}

// ====== 分布式锁 ======

func lockKey(stream, messageID string) string {
	return fmt.Sprintf("lock:stream:%s:message:%s", stream, messageID)
}

func (w *Worker) acquireLock(ctx context.Context, key string) (bool, error) {
	return w.RDB.SetNX(ctx, key, w.ConsumerName, w.LockTTL).Result()
}

func (w *Worker) releaseLock(ctx context.Context, key string) error {
	script := `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`
	_, err := w.RDB.Eval(ctx, script, []string{key}, w.ConsumerName).Result()
	if err == redis.Nil {
		return nil
	}
	return err
}

func (w *Worker) renewLock(ctx context.Context, key string) (bool, error) {
	script := `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("expire", KEYS[1], ARGV[2]) else return 0 end`
	v, err := w.RDB.Eval(ctx, script, []string{key}, w.ConsumerName, int(w.LockTTL.Seconds())).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, err
	}
	n, _ := v.(int64)
	return n == 1, nil
}

// ====== 工具 ======

// parseBusiness 按架构 §7 三字段解析:task_id / task_part_name / hosts(JSON 编码字符串数组)。
func parseBusiness(m redis.XMessage) (*BusinessMessage, error) {
	bm := &BusinessMessage{}
	if v, ok := m.Values["task_id"].(string); ok {
		id, _ := strconv.ParseUint(v, 10, 64)
		bm.TaskID = id
	}
	if v, ok := m.Values["task_part_name"].(string); ok {
		bm.TaskPartName = v
	}
	if v, ok := m.Values["hosts"].(string); ok && v != "" {
		if err := json.Unmarshal([]byte(v), &bm.Hosts); err != nil {
			return nil, fmt.Errorf("invalid hosts json: %w", err)
		}
	}
	if bm.TaskID == 0 || bm.TaskPartName == "" {
		return nil, errors.New("invalid business message")
	}
	return bm, nil
}

func podHostname() string {
	if v := os.Getenv("POD_NAME"); v != "" {
		return v
	}
	h, _ := os.Hostname()
	if h == "" {
		return uuid.New().String()
	}
	return h
}
