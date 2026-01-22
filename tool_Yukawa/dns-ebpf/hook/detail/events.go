// Package detail 定义 detail 模式下 eBPF 事件的抽象及解码器注册机制。
package detail

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Event 表示一次解码后的 eBPF 事件，最终会被编码为 JSON。
type Event interface {
	BuildPayload(info map[string]interface{}) (map[string]interface{}, error)
}

// EventDecoder 负责将 ring buffer 中的原始二进制解析成 Event。
type EventDecoder interface {
	Decode(rawSample []byte) (Event, error)
}

// EventDecoderFactory 用于创建具体的 EventDecoder。
type EventDecoderFactory func() EventDecoder

var (
	// decoderRegistry 保存注册的解码器工厂函数，由名称索引。
	decoderRegistry = make(map[string]EventDecoderFactory)
	// decoderRegistryMu 保护解码器注册表，避免并发读写冲突。
	decoderRegistryMu sync.RWMutex
)

// RegisterEventDecoder 将解码器工厂注册到全局表中。
func RegisterEventDecoder(name string, factory EventDecoderFactory) {
	if name == "" {
		panic("detail: event decoder name must not be empty")
	}
	if factory == nil {
		panic("detail: event decoder factory must not be nil")
	}
	decoderRegistryMu.Lock()
	decoderRegistry[name] = factory
	decoderRegistryMu.Unlock()
}

// newEventDecoder 根据名称实例化一个事件解码器。
func newEventDecoder(name string) (EventDecoder, error) {
	decoderRegistryMu.RLock()
	factory, ok := decoderRegistry[name]
	decoderRegistryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("detail: unknown event decoder %q", name)
	}
	return factory(), nil
}

const defaultEventDecoderName = "bind_9_16_2"

// EncodeEvent 将 Event 拼装成下游易消费的 JSON。
func EncodeEvent(event Event, info map[string]interface{}) ([]byte, error) {
	payload, err := event.BuildPayload(info)
	if err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}
