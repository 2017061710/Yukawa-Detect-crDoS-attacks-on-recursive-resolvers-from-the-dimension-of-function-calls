package model

// FuncEvent 是普通模式 ring buffer 中使用的最小事件结构，包含时间戳与进程信息。
type FuncEvent struct {
	Timestamp_boot_ns uint64
	Tgid_pid          uint64
	Hook_id           int32
	Pad_cgo_0         [4]byte
}
