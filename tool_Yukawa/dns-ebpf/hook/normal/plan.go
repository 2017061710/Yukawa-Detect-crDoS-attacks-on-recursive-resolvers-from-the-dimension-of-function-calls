package normal

import (
	"fmt"
)

const (
	// PositionEntry 表示函数入口处的 UProbe。
	PositionEntry Position = "entry"
	// PositionReturn 表示函数返回处的 Uretprobe。
	PositionReturn Position = "return"
)

// Position 描述 hook 在函数的哪个生命周期触发。
type Position string

// Target 记录单个需要 hook 的函数及其所在二进制。
type Target struct {
	BinPath         string   `json:"file_name"`
	Symbol          string   `json:"func_name"`
	DemangledSymbol string   `json:"demangled_func_name"`
	Position        Position `json:"position"`
}

// Point 将 Target 与唯一 ID 绑定，方便写入 eBPF 事件。
type Point struct {
	ID   int32
	Item Target
}

// Plan 是带次序的 Hook 列表，用于 Attach 流程。
type Plan []Point

// Validate 校验 Plan 中的 ID 是否唯一且非负。
func (p Plan) Validate() error {
	seen := make(map[int32]struct{}, len(p))
	for _, point := range p {
		if point.ID < 0 {
			return fmt.Errorf("negative hook id %d for %s", point.ID, point.Item.Symbol)
		}
		if _, ok := seen[point.ID]; ok {
			return fmt.Errorf("duplicated hook id %d", point.ID)
		}
		seen[point.ID] = struct{}{}
	}
	return nil
}

// Lookup 将 Plan 转换为 map[id]Target，便于事件快速查找。
func (p Plan) Lookup() map[int32]Target {
	result := make(map[int32]Target, len(p))
	for _, point := range p {
		result[point.ID] = point.Item
	}
	return result
}
