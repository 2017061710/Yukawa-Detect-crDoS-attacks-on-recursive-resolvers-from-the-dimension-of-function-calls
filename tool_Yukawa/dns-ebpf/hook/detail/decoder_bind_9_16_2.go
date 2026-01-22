package detail

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"dns-ebpf/hook/model"
)

func init() {
	RegisterEventDecoder("bind_9_16_2", func() EventDecoder {
		return &bind9162Decoder{}
	})
}

// bind9162Decoder 实现了 BIND 9.16.2 的事件解码逻辑。
type bind9162Decoder struct{}

// Decode 将 ring buffer 样本解析成模型事件，便于后续封装业务字段。
func (d *bind9162Decoder) Decode(rawSample []byte) (Event, error) {
	var event model.Bind_9_16_2_Event_Kernel
	if err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decode bind_9_16_2 event: %w", err)
	}
	return bind9162Event{event: event}, nil
}

// bind9162Event 包装原始结构体，提供通用 Payload 接口。
type bind9162Event struct {
	event model.Bind_9_16_2_Event_Kernel
}

// BuildPayload 拼装 detail 事件字段，并尝试通过 hookIDs 转换友好名称。
func (e bind9162Event) BuildPayload(info map[string]interface{}) (map[string]interface{}, error) {
	hookIDs, _ := info["hookIDs"].(map[int32]string)
	payload := map[string]interface{}{
		"Timestamp_boot_ns": e.event.Timestamp_boot_ns,
		"Tgid_pid":          e.event.Tgid_pid,
		"Hook_id":           e.event.Hook_id,
		"recursive_domain":  e.event.NameString(),
		"Type":              e.event.Type,
		"Transaction_id":    e.event.Transaction_id,
	}
	if hookIDs != nil {
		if name, ok := hookIDs[e.event.Hook_id]; ok {
			payload["Hook_name"] = name
		}
	}
	return payload, nil
}
