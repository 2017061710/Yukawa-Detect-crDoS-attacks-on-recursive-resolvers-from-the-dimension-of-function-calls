package output

import (
	"time"
)

// EventListenOptions 描述 hook 事件输出目标（文件或 Redis）。
type EventListenOptions struct {
	File  *FileOutputOptions
	Redis *RedisOutputOptions
}

// HasOutputs 判断是否配置了任意输出通道。
func (o EventListenOptions) HasOutputs() bool {
	return o.File != nil || o.Redis != nil
}

// FileOutputOptions 控制写入文件的事件输出。
type FileOutputOptions struct {
	Path string
}

// RedisOutputOptions 控制写入 Redis 的事件输出。
type RedisOutputOptions struct {
	Address        string
	DB             int
	Password       string
	ListKey        string
	ConnectTimeout time.Duration
	IOTimeout      time.Duration
}
