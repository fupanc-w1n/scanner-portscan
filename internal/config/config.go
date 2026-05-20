// Package scannerconfig 解析 Pod 启动配置 /app/config/config.json。
// 与 backend/internal/policy.PodConfig 字段一一对应。Worker 启动时调用 Load 即可。
package scannerconfig

import (
	"encoding/json"
	"fmt"
	"os"
)

// Scheduler Pod 连接调度层 Redis/MySQL 需要的字段
type Scheduler struct {
	InternalIP string `json:"internal_ip"`
	RedisPort  int    `json:"redis_port"`
	MySQLPort  int    `json:"mysql_port"`
}

// Redis Pod 启动后读取的 Redis 相关参数
type Redis struct {
	Stream             string `json:"stream"`
	Group              string `json:"group"`
	ControlStream      string `json:"control_stream"`
	ControlBroadcast   bool   `json:"control_broadcast"`
	LockTTLSeconds     int    `json:"lock_ttl_seconds"`
	LockRenewSeconds   int    `json:"lock_renew_seconds"`
	PendingIdleSeconds int    `json:"pending_idle_seconds"`
}

// Downstream 单条下游元数据
type Downstream struct {
	Module string `json:"module"`
	Stream string `json:"stream"`
}

// Workflow 当前模块允许投递的直接下游
type Workflow struct {
	Downstreams map[string]Downstream `json:"downstreams"`
}

// ServiceDict 弱口令字典
type ServiceDict struct {
	Username []string `json:"username"`
	Password []string `json:"password"`
}

// Config Pod 启动配置(对应 ConfigMap Data["config.json"])
type Config struct {
	PolicyID  uint64    `json:"policy_id"`
	Module    string    `json:"module"`
	Scheduler Scheduler `json:"scheduler"`
	Redis     Redis     `json:"redis"`
	Workflow  Workflow  `json:"workflow"`

	// module_config 字段松散,Pod 自己按需读取
	ModuleConfig json.RawMessage `json:"module_config"`
}

// Load 从 DAST_CONFIG 指向的文件加载;默认 /app/config/config.json。
func Load() (*Config, error) {
	path := os.Getenv("DAST_CONFIG")
	if path == "" {
		path = "/app/config/config.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Module == "" {
		return nil, fmt.Errorf("invalid config: module empty")
	}
	return &c, nil
}

// PortScanConfig 模块运行参数(端口扫描)
type PortScanConfig struct {
	Ports []string `json:"ports"`
	QPS   int      `json:"qps"`
}

// NmapConfig 模块运行参数(服务识别)
type NmapConfig struct {
	QPS int `json:"qps"`
}

// NucleiConfig 模块运行参数(Nuclei)
type NucleiConfig struct {
	QPS         int      `json:"qps"`
	TemplateIDs []string `json:"template_ids"`
}

// WeakPassConfig 模块运行参数(弱口令)
type WeakPassConfig struct {
	QPS        int                    `json:"qps"`
	Dictionary map[string]ServiceDict `json:"dictionary"`
}

// ParsePortScan 解析端口扫描 module_config
func (c *Config) ParsePortScan() (*PortScanConfig, error) {
	out := &PortScanConfig{}
	if len(c.ModuleConfig) == 0 {
		return out, nil
	}
	return out, json.Unmarshal(c.ModuleConfig, out)
}

// ParseNmap 解析 nmap module_config
func (c *Config) ParseNmap() (*NmapConfig, error) {
	out := &NmapConfig{}
	if len(c.ModuleConfig) == 0 {
		return out, nil
	}
	return out, json.Unmarshal(c.ModuleConfig, out)
}

// ParseNuclei 解析 nuclei module_config
func (c *Config) ParseNuclei() (*NucleiConfig, error) {
	out := &NucleiConfig{}
	if len(c.ModuleConfig) == 0 {
		return out, nil
	}
	return out, json.Unmarshal(c.ModuleConfig, out)
}

// ParseWeakPass 解析弱口令 module_config
func (c *Config) ParseWeakPass() (*WeakPassConfig, error) {
	out := &WeakPassConfig{}
	if len(c.ModuleConfig) == 0 {
		return out, nil
	}
	return out, json.Unmarshal(c.ModuleConfig, out)
}

// MySQLAddr 返回 Pod 应该连接的 MySQL 地址
func (c *Config) MySQLAddr() string {
	return fmt.Sprintf("%s:%d", c.Scheduler.InternalIP, c.Scheduler.MySQLPort)
}

// RedisAddr 返回 Pod 应该连接的 Redis 地址
func (c *Config) RedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Scheduler.InternalIP, c.Scheduler.RedisPort)
}
