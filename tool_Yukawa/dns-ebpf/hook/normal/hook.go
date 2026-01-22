// Package normal 提供自动化构建普通模式 hook 的能力，使用动态生成的 eBPF 程序收集函数命中。
package normal

import (
	"dns-ebpf/hook/model"
	"dns-ebpf/hook/output"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	// hookEventMapName 是 normal 模式 ring buffer map 的名称。
	hookEventMapName = "bind_ebpf_map"
	// hookProgPrefix 用于构造每个内联生成程序的名称，便于调试。
	hookProgPrefix = "bind_ebpf_"
	// closeLinkWorkerCap 限制并发关闭 eBPF link 的 goroutine 数，避免过度创建。
	closeLinkWorkerCap = 16
)

// Session 维护 normal 模式所需的内核对象（map、program link 等）。
type Session struct {
	eventMap  *ebpf.Map
	lookup    map[int32]Target
	progLinks map[int32]link.Link
}

// normalEventPayload 是对 ring buffer 事件的 JSON 友好封装。
type normalEventPayload struct {
	TimestampBootNS uint64 `json:"timestamp_boot_ns"`
	Tgid            uint32 `json:"tgid"`
	Pid             uint32 `json:"pid"`
	HookID          int32  `json:"hook_id"`
	BinPath         string `json:"bin_path"`
	FuncName        string `json:"func_name"`
	DemangledName   string `json:"demangled_func_name"`
	Position        string `json:"position"`
}

// MapID 查询 ring buffer map 的 ID，方便写入共享文件。
func (s *Session) MapID() (uint32, error) {
	info, err := s.eventMap.Info()
	if err != nil {
		return 0, fmt.Errorf("getting map info: %w", err)
	}
	mapID, ok := info.ID()
	if !ok {
		return 0, errors.New("map ID not found in map info")
	}
	return uint32(mapID), nil
}

// DumpHookItems 将 hook 计划输出为 JSON，方便排查/共享。
func (s *Session) DumpHookItems(jsonFilePath string) error {
	jsonData, err := encodeJSON(s.lookup, true)
	if err != nil {
		return fmt.Errorf("marshaling hook items: %w", err)
	}
	return os.WriteFile(jsonFilePath, jsonData, 0o644)
}

// Close 释放 eBPF map 及附着的 link。
func (s *Session) Close() {
	if s.eventMap != nil {
		s.eventMap.Close()
	}
	closeLinksInParallel(s.progLinks)
}

// CloseFast 在进程即将退出时使用，不等待所有 link 关闭，交给内核在进程结束时清理。
// 通过快速关闭 event map 来唤醒监听协程，减少 Ctrl+C 时的阻塞时间。
func (s *Session) CloseFast() {
	if s.eventMap != nil {
		s.eventMap.Close()
	}
	if len(s.progLinks) == 0 {
		return
	}
	go closeLinksInParallel(s.progLinks)
}

// Listen 阻塞监听事件
func (s *Session) Listen(options output.EventListenOptions) error {
	if !options.HasOutputs() {
		return errors.New("normal mode requires event output configuration")
	}

	var (
		logger    *output.HookLogger
		redisSink *output.RedisWriter
		err       error
	)

	if options.File != nil {
		if options.File.Path == "" {
			return errors.New("file output path is empty")
		}
		logger, err = output.NewHookLogger(options.File.Path, 8*1024*1024, 1*time.Second)
		if err != nil {
			return fmt.Errorf("creating hook logger: %w", err)
		}
	}

	if options.Redis != nil {
		redisSink, err = output.NewRedisWriter(*options.Redis)
		if err != nil {
			if logger != nil {
				logger.Close()
			}
			return fmt.Errorf("initializing redis writer: %w", err)
		}
	}

	funcReader, err := ringbuf.NewReader(s.eventMap)
	if err != nil {
		if logger != nil {
			logger.Close()
		}
		if redisSink != nil {
			redisSink.Close()
		}
		return fmt.Errorf("creating func name reader: %s", err)
	}

	go func(logger *output.HookLogger, redisSink *output.RedisWriter) {
		defer funcReader.Close()
		if logger != nil {
			defer logger.Close()
		}
		if redisSink != nil {
			defer redisSink.Close()
		}
		var event model.FuncEvent
		for {
			data, err := funcReader.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				log.Printf("reading event error: %s", err)
				continue
			}
			if err := binary.Read(bytes.NewBuffer(data.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}
			hookItem, ok := s.lookup[event.Hook_id]
			if !ok {
				continue
			}
			payload := buildNormalEventPayload(event, hookItem)
			encoded, err := encodeJSON(payload, false)
			if err != nil {
				log.Printf("encoding normal event error: %s", err)
				continue
			}
			if logger != nil {
				if err := logger.Log(string(encoded) + "\n"); err != nil {
					log.Printf("writing event log error: %s", err)
				}
			}
			if redisSink != nil {
				if err := redisSink.PushJSON(encoded); err != nil {
					log.Printf("pushing event to redis error: %s", err)
				}
			}
		}
	}(logger, redisSink)
	return nil
}

// buildNormalEventPayload 将 eBPF 原始事件与 hook 配置融合，得到完整的上下文信息。
func buildNormalEventPayload(event model.FuncEvent, hook Target) normalEventPayload {
	return normalEventPayload{
		TimestampBootNS: event.Timestamp_boot_ns,
		Tgid:            uint32(event.Tgid_pid >> 32),
		Pid:             uint32(event.Tgid_pid & 0xffffffff),
		HookID:          event.Hook_id,
		BinPath:         hook.BinPath,
		FuncName:        hook.Symbol,
		DemangledName:   hook.DemangledSymbol,
		Position:        string(hook.Position),
	}
}

// encodeJSON 生成可选缩进且不转义 HTML 的 JSON。
func encodeJSON(v interface{}, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	// 去掉结尾换行，方便写入文件或 Redis。
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// Attach 根据 Plan 创建 ring buffer、构建内联 asm 程序并附加到目标函数。
func Attach(plan Plan, verbose bool) (*Session, error) {
	if len(plan) == 0 {
		return nil, errors.New("no hook items")
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	eventMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       hookEventMapName,
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 24,
	})
	if err != nil {
		return nil, err
	}

	s := &Session{
		eventMap:  eventMap,
		lookup:    plan.Lookup(),
		progLinks: make(map[int32]link.Link, len(plan)),
	}

	execCache := newExecutableCache()
	defer execCache.Close()

	for _, point := range plan {
		if verbose {
			log.Printf("hooking %s:%s(%s) => id %d", point.Item.BinPath, point.Item.Symbol, point.Item.Position, point.ID)
		}
		prog, err := buildRingbufProgram(eventMap, point.ID)
		if err != nil {
			s.Close()
			return nil, err
		}
		linkHandle, err := attachHook(point.Item, prog, execCache)
		prog.Close()
		if err != nil {
			s.Close()
			return nil, err
		}
		s.progLinks[point.ID] = linkHandle
	}

	return s, nil
}

// buildRingbufProgram 生成一段最小的 eBPF 程序：记录时间戳与 PID/TID 并写入 ring buffer。
func buildRingbufProgram(eventMap *ebpf.Map, hookID int32) (*ebpf.Program, error) {
	spec := &ebpf.ProgramSpec{
		Name: fmt.Sprintf("%s%d", hookProgPrefix, hookID),
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.FnKtimeGetBootNs.Call(),
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
			asm.FnGetCurrentPidTgid.Call(),
			asm.Mov.Imm(asm.R1, hookID),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.Word),
			asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -24),
			asm.LoadMapPtr(asm.R1, eventMap.FD()),
			asm.Mov.Imm(asm.R3, 24),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnRingbufOutput.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	}
	return ebpf.NewProgram(spec)
}

// attachHook 使用 link.Executable 将 eBPF 程序附着到指定符号的 entry/return。
func attachHook(item Target, prog *ebpf.Program, cache *executableCache) (link.Link, error) {
	ex, err := cache.Get(item.BinPath)
	if err != nil {
		return nil, err
	}
	switch item.Position {
	case PositionEntry:
		return ex.Uprobe(item.Symbol, prog, nil)
	case PositionReturn:
		return ex.Uretprobe(item.Symbol, prog, nil)
	default:
		return nil, fmt.Errorf("unknown hook item position: %s", item.Position)
	}
}

// executableCache 复用 link.OpenExecutable 结果，避免重复打开二进制。
type executableCache struct {
	handles map[string]*link.Executable
}

// newExecutableCache 创建 Executable 缓存，减少 open/close 频率。
func newExecutableCache() *executableCache {
	return &executableCache{
		handles: make(map[string]*link.Executable),
	}
}

// Get 返回缓存的 Executable，若不存在则打开并缓存。
func (c *executableCache) Get(path string) (*link.Executable, error) {
	if ex, ok := c.handles[path]; ok {
		return ex, nil
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}
	c.handles[path] = ex
	return ex, nil
}

// Close 在 normal 模式下无需执行实际动作，Executable 会在进程退出时释放。
func (c *executableCache) Close() {
	// link.Executable does not expose a Close method; cached handles
	// will be released when the process exits.
}

// closeLinksInParallel 并发关闭 link，减少 normal 模式下大量 hook 退出时的阻塞时间。
func closeLinksInParallel(links map[int32]link.Link) {
	if len(links) == 0 {
		return
	}

	workerCount := runtime.NumCPU()
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > closeLinkWorkerCap {
		workerCount = closeLinkWorkerCap
	}
	if workerCount > len(links) {
		workerCount = len(links)
	}

	jobs := make(chan link.Link, workerCount)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range jobs {
				if l != nil {
					l.Close()
				}
			}
		}()
	}

	for _, l := range links {
		jobs <- l
	}
	close(jobs)
	wg.Wait()
}
