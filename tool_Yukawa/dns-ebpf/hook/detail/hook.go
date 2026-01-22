// Package detail 提供手写 eBPF 程序在用户态的加载、附加与事件监听逻辑。
package detail

import (
	"dns-ebpf/hook/output"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Session 维护 detail 模式运行所需的 eBPF map、program、link 以及辅助信息。
type Session struct {
	maps         map[string]*ebpf.Map
	programLinks map[string]link.Link
	programs     map[string]*ebpf.Program
	info         map[string]interface{}
	eventDecoder EventDecoder
}

// getFilterObjs 根据配置动态裁剪 bpfObjects，仅保留需要加载的 map/program。
func (s *Session) getFilterObjs() (interface{}, error) {
	baseVal := reflect.ValueOf(&bpfObjects{}).Elem()
	baseType := baseVal.Type()

	var newFields []reflect.StructField
	var newValues []reflect.Value
	var process func(t reflect.Type, v reflect.Value)
	process = func(t reflect.Type, v reflect.Value) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldVal := v.Field(i)

			// 如果是匿名嵌套结构体，递归处理其字段
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				process(field.Type, fieldVal)
				continue
			}

			ebpfTag := field.Tag.Get("ebpf")
			if ebpfTag == "" {
				continue
			}

			fieldType := field.Type

			if fieldType == reflect.TypeOf((*ebpf.Program)(nil)) {
				_, ok := s.programLinks[ebpfTag]
				if !ok {
					continue
				}
				newFields = append(newFields, field)
				newValues = append(newValues, fieldVal)
			}

			if fieldType == reflect.TypeOf((*ebpf.Map)(nil)) {
				_, ok := s.maps[ebpfTag]
				if !ok {
					continue
				}
				newFields = append(newFields, field)
				newValues = append(newValues, fieldVal)
			}
		}
	}

	process(baseType, baseVal)

	newStructType := reflect.StructOf(newFields)
	newStruct := reflect.New(newStructType).Elem()

	for i := range newFields {
		newStruct.Field(i).Set(newValues[i])
	}

	return newStruct.Addr().Interface(), nil
}

// fillByObjs 将 loadBpfObjects 填充出的 map/program 引用保存到 Session。
func (s *Session) fillByObjs(objs interface{}) error {
	baseVal := reflect.ValueOf(objs).Elem()
	baseType := baseVal.Type()

	var process func(t reflect.Type, v reflect.Value)
	process = func(t reflect.Type, v reflect.Value) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldVal := v.Field(i)

			// 如果是匿名嵌套结构体，递归处理其字段
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				process(field.Type, fieldVal)
				continue
			}

			ebpfTag := field.Tag.Get("ebpf")
			if ebpfTag == "" {
				continue
			}

			fieldType := field.Type

			if fieldType == reflect.TypeOf((*ebpf.Program)(nil)) {
				s.programs[ebpfTag] = fieldVal.Interface().(*ebpf.Program)
			}

			if fieldType == reflect.TypeOf((*ebpf.Map)(nil)) {
				s.maps[ebpfTag] = fieldVal.Interface().(*ebpf.Map)
			}
		}
	}

	process(baseType, baseVal)

	return nil
}

// loadObjects 加载所需的 eBPF 对象，并在 verbose 模式下打印详细信息。
func (s *Session) loadObjects(verbose bool) error {
	objs, err := s.getFilterObjs()
	if err != nil {
		return fmt.Errorf("getting filter objects: %w", err)
	}
	err = loadBpfObjects(objs, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if verbose && errors.As(err, &ve) {
			log.Printf("verifier error: %+v\n", ve)
		}
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	s.fillByObjs(objs)
	err = nil
	for progName, prog := range s.programs {
		if prog == nil {
			if verbose {
				log.Printf("program %s not found in spec\n", progName)
			}
			err = fmt.Errorf("program %s not found in spec", progName)
		} else if verbose {
			log.Printf("program %s loaded\n", progName)
		}
	}
	for mapName, hMap := range s.maps {
		if hMap == nil {
			if verbose {
				log.Printf("map %s not found in spec\n", mapName)
			}
			err = fmt.Errorf("map %s not found in spec", mapName)
		} else if verbose {
			log.Printf("map %s loaded\n", mapName)
		}
	}
	return err
}

// Attach 根据配置加载 eBPF 程序、附加 uprobe，并初始化事件解码器。
func Attach(config *Config, verbose bool) (*Session, error) {
	session := Session{
		maps:         make(map[string]*ebpf.Map),
		programs:     make(map[string]*ebpf.Program),
		programLinks: make(map[string]link.Link),
	}

	for _, hMap := range config.Maps {
		session.maps[hMap.Name] = nil
	}
	for _, hProg := range config.Programs {
		session.programLinks[hProg.Name] = nil
		session.programs[hProg.Name] = nil
	}

	if err := session.loadObjects(verbose); err != nil {
		return nil, err
	}

	for _, hProg := range config.Programs {
		if verbose {
			log.Printf("hooking %s:%s(%s)\n", hProg.BinPath, hProg.Symbol, hProg.Position)
		}
		prog := session.programs[hProg.Name]
		ex, err := link.OpenExecutable(hProg.BinPath)
		if err != nil {
			return nil, fmt.Errorf("open executable %s: %w", hProg.BinPath, err)
		}
		switch HookPosition(hProg.Position) {
		case HookPositionEntry:
			up, err := ex.Uprobe(hProg.Symbol, prog, nil)
			if err != nil {
				return nil, err
			}
			session.programLinks[hProg.Name] = up
		case HookPositionReturn:
			up, err := ex.Uretprobe(hProg.Symbol, prog, nil)
			if err != nil {
				return nil, err
			}
			session.programLinks[hProg.Name] = up
		default:
			return nil, fmt.Errorf("unknown position %s for %s", hProg.Position, hProg.Name)
		}
	}
	for _, infoItem := range config.Infos {
		for key, path := range infoItem {
			switch key {
			case "hook_id":
				hookIDs, err := ParseHookIDMap(path)
				if err != nil {
					return nil, fmt.Errorf("parsing hook id map from %s: %w", path, err)
				}
				if session.info == nil {
					session.info = make(map[string]interface{})
				}
				session.info["hookIDs"] = hookIDs
			default:
				return nil, fmt.Errorf("unknown info key %s", key)
			}
		}
	}

	decoderName := config.DecoderName()
	decoder, err := newEventDecoder(decoderName)
	if err != nil {
		return nil, fmt.Errorf("creating event decoder %q: %w", decoderName, err)
	}
	session.eventDecoder = decoder

	return &session, nil
}

// Close 释放所有 eBPF 资源以及附着关系。
func (s *Session) Close() {
	for _, prog := range s.programs {
		if prog != nil {
			prog.Close()
		}
	}
	for _, linkHandle := range s.programLinks {
		if linkHandle != nil {
			linkHandle.Close()
		}
	}
	for _, hookEventMap := range s.maps {
		if hookEventMap != nil {
			hookEventMap.Close()
		}
	}
}

// Listen 按配置订阅 ring buffer，并将事件写入文件或 Redis。
func (s *Session) Listen(options output.EventListenOptions) error {
	if !options.HasOutputs() {
		return fmt.Errorf("no event outputs configured for detail mode")
	}

	var (
		logger     *output.HookLogger
		redisSink  *output.RedisWriter
		err        error
		eventMap   = s.maps["hook_event_map"]
		// closeFuncs 收集 Listen 完成或异常退出时需要依次清理的资源。
		closeFuncs []func()
	)

	if options.File != nil {
		if options.File.Path == "" {
			return fmt.Errorf("file output path is empty")
		}
		logger, err = output.NewHookLogger(options.File.Path, 8*1024*1024, 1*time.Second)
		if err != nil {
			return fmt.Errorf("creating hook logger: %w", err)
		}
		closeFuncs = append(closeFuncs, func() {
			logger.Close()
		})
	}

	if options.Redis != nil {
		redisSink, err = output.NewRedisWriter(*options.Redis)
		if err != nil {
			for _, fn := range closeFuncs {
				fn()
			}
			return fmt.Errorf("initializing redis writer: %w", err)
		}
		closeFuncs = append(closeFuncs, func() {
			redisSink.Close()
		})
	}

	if eventMap == nil {
		for _, fn := range closeFuncs {
			fn()
		}
		return errors.New("hook_event_map map not found")
	}
	if s.eventDecoder == nil {
		for _, fn := range closeFuncs {
			fn()
		}
		return errors.New("event decoder not configured")
	}

	funcReader, err := ringbuf.NewReader(eventMap)
	if err != nil {
		for _, fn := range closeFuncs {
			fn()
		}
		return fmt.Errorf("creating func name reader: %s", err)
	}

	go func() {
		defer funcReader.Close()
		for _, fn := range closeFuncs {
			defer fn()
		}
		for {
			data, err := funcReader.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				log.Printf("reading event error: %s", err)
				continue
			}
			event, err := s.eventDecoder.Decode(data.RawSample)
			if err != nil {
				log.Printf("decoding event error: %s", err)
				continue
			}
			payload, err := EncodeEvent(event, s.info)
			if err != nil {
				log.Printf("encode detail event error: %s", err)
				continue
			}
			if logger != nil {
				if err := logger.Log(string(payload) + "\n"); err != nil {
					log.Printf("writing event log error: %s", err)
				}
			}
			if redisSink != nil {
				if err := redisSink.PushJSON(payload); err != nil {
					log.Printf("pushing event to redis error: %s", err)
				}
			}
		}
	}()
	return nil
}
