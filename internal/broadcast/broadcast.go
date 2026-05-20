// Package broadcast 实现控制流 XREAD + lastID 广播读取(架构 §6.4)。
// Pod 独立维护 lastControlID,所有 Pod 都能读到同一条 pause/resume/terminate。
package broadcast

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ControlMessage 与后端 redisstream.ControlMessage 字段对齐
type ControlMessage struct {
	EventID  string
	TaskID   uint64
	PolicyID uint64
	Action   string
}

// State 维护 pausedTaskIDs / terminatedTaskIDs 集合,线程安全
type State struct {
	mu         sync.RWMutex
	paused     map[uint64]struct{}
	terminated map[uint64]struct{}
}

// NewState 构造
func NewState() *State {
	return &State{paused: map[uint64]struct{}{}, terminated: map[uint64]struct{}{}}
}

// Apply 根据控制消息更新本地状态
func (s *State) Apply(m ControlMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Action {
	case "pause":
		s.paused[m.TaskID] = struct{}{}
	case "resume":
		delete(s.paused, m.TaskID)
	case "terminate":
		s.terminated[m.TaskID] = struct{}{}
	}
}

// IsPaused 判断
func (s *State) IsPaused(taskID uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.paused[taskID]
	return ok
}

// IsTerminated 判断
func (s *State) IsTerminated(taskID uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.terminated[taskID]
	return ok
}

// Start 启动控制流监听 goroutine。lastID 初始用 "$" 只读新消息。
// 调用方应在 ctx 取消时退出。
func Start(ctx context.Context, rdb *redis.Client, controlStream string, state *State) {
	go func() {
		lastID := "$"
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			streams, err := rdb.XRead(ctx, &redis.XReadArgs{
				Streams: []string{controlStream, lastID},
				Count:   10,
				Block:   5 * time.Second,
			}).Result()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				// 网络抖动等,sleep 后重试
				time.Sleep(time.Second)
				continue
			}
			for _, s := range streams {
				for _, msg := range s.Messages {
					lastID = msg.ID
					cm := parse(msg)
					if cm.Action == "" {
						continue
					}
					state.Apply(cm)
				}
			}
		}
	}()
}

func parse(msg redis.XMessage) ControlMessage {
	cm := ControlMessage{}
	if v, ok := msg.Values["event_id"].(string); ok {
		cm.EventID = v
	}
	if v, ok := msg.Values["action"].(string); ok {
		cm.Action = v
	}
	if v, ok := msg.Values["task_id"].(string); ok {
		fmt.Sscanf(v, "%d", &cm.TaskID)
	}
	if v, ok := msg.Values["policy_id"].(string); ok {
		fmt.Sscanf(v, "%d", &cm.PolicyID)
	}
	return cm
}
