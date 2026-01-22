// Package main 是 dns-ebpf 的入口，负责解析参数、准备运行时目录并启动不同的 Hook 模式。
package main

import (
	"dns-ebpf/hook/detail"
	"dns-ebpf/hook/normal"
	hookoutput "dns-ebpf/hook/output"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

const (
	defaultNormalConfig = "config/bind/9_16_2/normal.yaml"
	defaultDetailConfig = "config/bind/9_16_2/detail.yaml"
)

// logOutput 表示运行日志的输出位置。
type logOutput string

const (
	logOutputFile    logOutput = "file"
	logOutputConsole logOutput = "console"
)

// hookMode 区分普通模式与细粒度 detail 模式。
type hookMode string

const (
	modeNormal hookMode = "normal"
	modeDetail hookMode = "detail"
)

// hookListener 抽象出 normal/detail 两种模式的公共监听行为。
type hookListener interface {
	Listen(hookoutput.EventListenOptions) error
	Close()
}

// runtimePaths 统一记录一次运行生成的关键文件路径。
type runtimePaths struct {
	recordDir    string // 本次运行的根目录
	logFile      string // 运行日志文件
	eventLogFile string // 事件输出日志文件
	hookItems    string // 记录 normal 模式 hook 列表
	mapInfo      string // 记录 eBPF map 信息
}

func main() {
	var (
		configPathFlag = flag.String("c", "", "Path to the hook configuration file")
		modeFlag       = flag.String("mode", string(modeDetail), "Hook mode: normal (coarse stats) or detail (custom eBPF)")
		verboseFlag    = flag.Bool("v", false, "Whether output real-time hook progress")
		eventOutput    = flag.Bool("e", false, "Whether output event log")
		eventTargets   = flag.String("event-targets", "file", "Comma separated event outputs (file,redis)")
		logOutputFlag  = flag.String("log-output", string(logOutputConsole), "Where to write runtime logs: file or console")
		redisAddr      = flag.String("redis-addr", "localhost:6379", "Redis address for event output")
		redisDB        = flag.Int("redis-db", 0, "Redis database index for event output")
		redisKey       = flag.String("redis-key", "dns_events", "Redis list key for event output")
		redisPassword  = flag.String("redis-password", "", "Redis password for event output")
	)
	flag.Parse()

	targetCfg, err := parseEventTargets(*eventTargets)
	if err != nil {
		log.Fatalf("invalid event targets: %v", err)
	}

	mode, err := parseMode(*modeFlag)
	if err != nil {
		log.Fatalf("invalid hook mode %q: %v", *modeFlag, err)
	}

	configPath := selectConfigPath(mode, *configPathFlag)

	// 捕获中断信号，确保退出时能够清理资源。
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 设置内存锁定限制，避免加载 eBPF 程序时失败。
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	paths, err := prepareRuntimePaths(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	logDest, err := parseLogOutput(*logOutputFlag)
	if err != nil {
		log.Fatal(err)
	}
	logCloser, err := initLogger(paths.logFile, logDest)
	if err != nil {
		log.Fatalf("open log file error: %s", err)
	}
	if logCloser != nil {
		defer logCloser.Close()
	}

	log.Printf("Runtime directory: %s", paths.recordDir)
	if logDest == logOutputFile {
		log.Printf("Run log file: %s", paths.logFile)
	} else {
		log.Printf("Logging to console")
	}
	log.Printf("Using %s mode with config %s", mode, configPath)

	var runner hookListener
	switch mode {
	case modeNormal:
		runner, err = runNormalMode(configPath, paths, *verboseFlag)
	case modeDetail:
		runner, err = runDetailMode(configPath, *verboseFlag)
	default:
		err = fmt.Errorf("unsupported mode %q", mode)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer closeRunner(runner)

	if *eventOutput {
		outputs := hookoutput.EventListenOptions{}
		if targetCfg.file {
			outputs.File = &hookoutput.FileOutputOptions{Path: paths.eventLogFile}
			log.Printf("Event log file: %s", paths.eventLogFile)
		}
		if targetCfg.redis {
			outputs.Redis = &hookoutput.RedisOutputOptions{
				Address:  *redisAddr,
				DB:       *redisDB,
				Password: *redisPassword,
				ListKey:  *redisKey,
			}
			log.Printf("Redis event output enabled: %s db=%d key=%s", outputs.Redis.Address, outputs.Redis.DB, outputs.Redis.ListKey)
		}
		if outputs.HasOutputs() {
			if err := runner.Listen(outputs); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Println("Event logging disabled: no output target selected")
		}
	} else {
		log.Println("Event logging disabled (-e=false)")
	}

	log.Println("Hook listening...")
	log.Println("Press Ctrl+C to stop")
	<-stopper
	log.Println("Stopping hook...")
}

// parseMode 将字符串转换为 hookMode，确保用户输入受控。
func parseMode(raw string) (hookMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(modeNormal):
		return modeNormal, nil
	case string(modeDetail):
		return modeDetail, nil
	default:
		return "", fmt.Errorf("unknown mode %q", raw)
	}
}

// selectConfigPath 根据运行模式选择默认配置，允许命令行覆盖。
func selectConfigPath(mode hookMode, provided string) string {
	if provided != "" {
		return provided
	}
	switch mode {
	case modeNormal:
		return defaultNormalConfig
	case modeDetail:
		return defaultDetailConfig
	default:
		return defaultNormalConfig
	}
}

// closeRunner 根据具体模式选择合适的关闭策略。
// normal 模式在退出时不强制同步关闭全部 link，避免大量 hook 时阻塞退出；
// detail 模式保留原有同步关闭行为。
func closeRunner(r hookListener) {
	if r == nil {
		return
	}
	if normalSession, ok := r.(*normal.Session); ok {
		normalSession.CloseFast()
		return
	}
	r.Close()
}

// prepareRuntimePaths 以当前时间创建运行目录，并返回相关文件路径。
func prepareRuntimePaths(now time.Time) (runtimePaths, error) {
	dirName := fmt.Sprintf("%d-%02d-%02d_%02d-%02d-%02d",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	recordDir := filepath.Join("record", dirName)
	if err := os.MkdirAll(recordDir, 0o755); err != nil {
		return runtimePaths{}, fmt.Errorf("mkdir %s: %w", recordDir, err)
	}
	return runtimePaths{
		recordDir:    recordDir,
		logFile:      filepath.Join(recordDir, "run.log"),
		eventLogFile: filepath.Join(recordDir, "events.log"),
		hookItems:    filepath.Join(recordDir, "hook_items.json"),
		mapInfo:      filepath.Join(recordDir, "map_info.json"),
	}, nil
}

// initLogger 根据目标切换日志输出并返回需要关闭的句柄。
func initLogger(logFile string, target logOutput) (io.Closer, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	switch target {
	case logOutputConsole:
		log.SetOutput(os.Stdout)
		return nil, nil
	case logOutputFile:
		f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err != nil {
			return nil, err
		}
		log.SetOutput(f)
		return f, nil
	default:
		return nil, fmt.Errorf("unknown log output target %q", target)
	}
}

// runNormalMode 加载普通模式配置、构建 hook 计划并启动 eBPF。
func runNormalMode(configPath string, paths runtimePaths, verbose bool) (*normal.Session, error) {
	log.Printf("Reading configuration file %s", configPath)
	config, err := normal.ReadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := config.InitHookFuncs(); err != nil {
		return nil, fmt.Errorf("init hook functions: %w", err)
	}
	plan, err := config.BuildPlan()
	if err != nil {
		return nil, fmt.Errorf("build hook plan: %w", err)
	}
	log.Println("Creating hook...")
	h, err := normal.Attach(plan, verbose)
	if err != nil {
		return nil, fmt.Errorf("creating normal hook: %w", err)
	}
	log.Printf("Hook successfully created: total %d hooks", len(plan))
	if err := h.DumpHookItems(paths.hookItems); err != nil {
		h.Close()
		return nil, fmt.Errorf("dump hook items: %w", err)
	}
	mapID, err := h.MapID()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("reading hook map id: %w", err)
	}
	if err := writeMapInfo(paths.mapInfo, mapID); err != nil {
		h.Close()
		return nil, fmt.Errorf("write map info: %w", err)
	}
	log.Printf("Map ID %d written to %s", mapID, paths.mapInfo)
	return h, nil
}

// runDetailMode 加载 detail 配置并启动 uprobe 监听流程。
func runDetailMode(configPath string, verbose bool) (*detail.Session, error) {
	log.Printf("Reading detailed configuration file %s", configPath)
	cfg, err := detail.ReadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("read detailed config: %w", err)
	}
	log.Println("Creating detail hook...")
	h, err := detail.Attach(cfg, verbose)
	if err != nil {
		return nil, fmt.Errorf("creating detail hook: %w", err)
	}
	return h, nil
}

// writeMapInfo 将 eBPF map ID 写入 JSON 文件，方便其他工具读取。
func writeMapInfo(filePath string, mapID uint32) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	type hookMapInfo struct {
		ID uint32 `json:"id"`
	}

	mapInfo := map[string]hookMapInfo{
		"hook_map": {ID: mapID},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(mapInfo); err != nil {
		return err
	}
	return nil
}

// eventTargetConfig 记录事件输出目标，用于驱动 Listen 逻辑。
type eventTargetConfig struct {
	file  bool
	redis bool
}

// parseEventTargets 解析命令行传入的事件输出列表。
func parseEventTargets(raw string) (eventTargetConfig, error) {
	var cfg eventTargetConfig
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		cfg.file = true
		return cfg, nil
	}
	parts := strings.Split(trimmed, ",")
	for _, part := range parts {
		target := strings.ToLower(strings.TrimSpace(part))
		switch target {
		case "", "file":
			cfg.file = true
		case "redis":
			cfg.redis = true
		case "none":
			// Explicitly ignore
		default:
			return cfg, fmt.Errorf("unknown event target %q", part)
		}
	}
	return cfg, nil
}

// parseLogOutput 解析日志输出目标。
func parseLogOutput(raw string) (logOutput, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(logOutputFile):
		return logOutputFile, nil
	case string(logOutputConsole):
		return logOutputConsole, nil
	default:
		return "", fmt.Errorf("unknown log output target %q", raw)
	}
}
