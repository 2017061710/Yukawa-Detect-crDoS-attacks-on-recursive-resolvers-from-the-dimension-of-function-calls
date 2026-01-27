package model

import (
	"fmt"
	"strings"
)

// Bind_9_16_2_Event_Kernel 对应 eBPF 侧写入 ring buffer 的结构体。
type Bind_9_16_2_Event_Kernel struct {
	Timestamp_boot_ns uint64
	Tgid_pid          uint64
	Hook_id           int32
	Transaction_id    uint16
	Name              [256]int8
	Type              uint16
}

// NameString 将 C 风格字符串 Name 转换为 Go 字符串。
func (e Bind_9_16_2_Event_Kernel) NameString() string {
	var nameBuilder strings.Builder
	for _, c := range e.Name {
		if c == 0 {
			break
		}
		nameBuilder.WriteByte(byte(c))
	}
	return strings.ToLower(nameBuilder.String())
	// return nameBuilder.String()
}

// ToString 将结构体格式化为可读输出，可选地替换 Hook ID 为名称。
func (e Bind_9_16_2_Event_Kernel) ToString(hookIDMap map[int32]string) string {
	name := e.NameString()

	// 如果 hookIDMap 中存在对应的名称，则使用映射名称
	if hookIDMap != nil {
		hook_name, exists := hookIDMap[e.Hook_id]
		if exists {
			return fmt.Sprintf(
				"DetailFuncEvent{\n  Timestamp_boot_ns: %d,\n  Tgid_pid: %d,\n  Hook_id: %d (%s),\n  Name: %s,\n  Type: %d,\n Transaction_id: %d\n}",
				e.Timestamp_boot_ns,
				e.Tgid_pid,
				e.Hook_id,
				hook_name,
				name,
				e.Type,
				e.Transaction_id,
			)
		}
	}
	return fmt.Sprintf(
		"DetailFuncEvent{\n  Timestamp_boot_ns: %d,\n  Tgid_pid: %d,\n  Hook_id: %d,\n  Name: %s,\n  Type: %d,\n Transaction_id: %d\n}",
		e.Timestamp_boot_ns,
		e.Tgid_pid,
		e.Hook_id,
		name,
		e.Type,
		e.Transaction_id,
	)
}
