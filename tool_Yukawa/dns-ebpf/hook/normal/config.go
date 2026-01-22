package normal

import (
	"bytes"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/ianlancetaylor/demangle"
	"gopkg.in/yaml.v2"
)

type sourceLanguage string

const (
	languageC   sourceLanguage = "c"
	languageCPP sourceLanguage = "c++"
)

// ExplicitTarget 描述针对某个符号的精细 hook 策略，可独立控制 Entry/Return。
type ExplicitTarget struct {
	Symbol          string `yaml:"symbol,omitempty"`
	DemangledSymbol string `yaml:"demangled_symbol,omitempty"`
	Entry           bool   `yaml:"entry"`
	Return          bool   `yaml:"return"`
}

// PatternRule 允许为每条 include/exclude 指定匹配作用域（raw/demangled/both）。
type PatternRule struct {
	Pattern string `yaml:"pattern"`
	Match   string `yaml:"match,omitempty"` // raw | demangled | both(default)
}

// PatternRules 支持字符串简写或对象形式。
type PatternRules []PatternRule

// UnmarshalYAML 兼容字符串列表和对象列表两种写法。
func (p *PatternRules) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw []interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	var rules []PatternRule
	for _, item := range raw {
		switch v := item.(type) {
		case string:
			rules = append(rules, PatternRule{Pattern: v})
		case map[interface{}]interface{}:
			var r PatternRule
			if pattern, ok := v["pattern"]; ok {
				r.Pattern = fmt.Sprint(pattern)
			}
			if match, ok := v["match"]; ok {
				r.Match = fmt.Sprint(match)
			}
			if r.Pattern == "" {
				return fmt.Errorf("pattern cannot be empty")
			}
			rules = append(rules, r)
		default:
			return fmt.Errorf("unsupported pattern item type %T", v)
		}
	}
	*p = rules
	return nil
}

// HookTarget 表示一个可执行文件的整体 hook 规则。
// 优先级说明：
//  1. Include > Exclude
//  2. Explicit > DefaultEntry/DefaultReturn
type HookTarget struct {
	Path          string           `yaml:"path"`
	Language      string           `yaml:"language,omitempty"`
	DefaultEntry  bool             `yaml:"default_entry,omitempty"`
	DefaultReturn bool             `yaml:"default_return,omitempty"`
	Include       PatternRules     `yaml:"include,omitempty"`
	Exclude       PatternRules     `yaml:"exclude,omitempty"`
	Explicit      []ExplicitTarget `yaml:"explicit,omitempty"`
}

// Config 汇总 normal 模式需要的全部 hook 目标。
type Config struct {
	Targets   []HookTarget `yaml:"targets"`
	hookFuncs map[string][]HookedSymbol
}

// HookedSymbol 保存生成 Plan 所需的符号信息，包括解码后的名称。
type HookedSymbol struct {
	Symbol    string
	Demangled string
	Entry     bool
	Return    bool
}

// SymbolInfo 描述从 ELF 读取到的符号原始名和解码名。
type SymbolInfo struct {
	Raw       string
	Demangled string
}

var demangleCache sync.Map

// GetHookFuncs 返回缓存的 hook 列表，必要时自动初始化。
func (c *Config) GetHookFuncs() map[string][]HookedSymbol {
	if c.hookFuncs == nil {
		c.hookFuncs = make(map[string][]HookedSymbol)
	}
	return c.hookFuncs
}

// InitHookFuncs 遍历目标 ELF，应用 include/exclude/explicit，生成最终 hook 列表。
func (c *Config) InitHookFuncs() error {
	c.hookFuncs = make(map[string][]HookedSymbol)
	for _, target := range c.Targets {
		funcs, err := readDefinedFunc(target.Path, parseLanguage(target.Language))
		if err != nil {
			return fmt.Errorf("failed to read defined functions from %s: %w", target.Path, err)
		}
		tmpExplicit := make(map[string]ExplicitTarget)
		tmpExplicitDemangled := make(map[string]ExplicitTarget)
		for _, explicit := range target.Explicit {
			if explicit.Symbol != "" {
				tmpExplicit[explicit.Symbol] = explicit
			}
			if explicit.DemangledSymbol != "" {
				tmpExplicitDemangled[explicit.DemangledSymbol] = explicit
			}
		}
		for _, f := range funcs {
			if explicit, ok := tmpExplicit[f.Raw]; ok {
				c.hookFuncs[target.Path] = append(c.hookFuncs[target.Path], HookedSymbol{
					Symbol:    f.Raw,
					Demangled: f.Demangled,
					Entry:     explicit.Entry,
					Return:    explicit.Return,
				})
				continue
			}
			if explicit, ok := tmpExplicitDemangled[f.Demangled]; ok {
				c.hookFuncs[target.Path] = append(c.hookFuncs[target.Path], HookedSymbol{
					Symbol:    f.Raw,
					Demangled: f.Demangled,
					Entry:     explicit.Entry,
					Return:    explicit.Return,
				})
				continue
			}
			if shouldIncludeFunc(f, target.Include, target.Exclude) {
				c.hookFuncs[target.Path] = append(c.hookFuncs[target.Path], HookedSymbol{
					Symbol:    f.Raw,
					Demangled: f.Demangled,
					Entry:     target.DefaultEntry,
					Return:    target.DefaultReturn,
				})
			}
		}
	}
	return nil
}

// BuildPlan 将 hook 列表转换为带 ID 的 Plan，ID 会按顺序自增。
func (c *Config) BuildPlan() (Plan, error) {
	if c.hookFuncs == nil {
		return nil, fmt.Errorf("hook functions not initialized")
	}
	var cnt int32
	var plan Plan
	for path, explicitHookTargets := range c.GetHookFuncs() {
		for _, explicit := range explicitHookTargets {
			if explicit.Entry {
				plan = append(plan, Point{
					ID: cnt,
					Item: Target{
						BinPath:         path,
						Symbol:          explicit.Symbol,
						DemangledSymbol: explicit.Demangled,
						Position:        PositionEntry,
					},
				})
				cnt++
			}
			if explicit.Return {
				plan = append(plan, Point{
					ID: cnt,
					Item: Target{
						BinPath:         path,
						Symbol:          explicit.Symbol,
						DemangledSymbol: explicit.Demangled,
						Position:        PositionReturn,
					},
				})
				cnt++
			}
		}
	}
	return plan, nil
}

func parseLanguage(raw string) sourceLanguage {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "c++", "cpp", "cxx":
		return languageCPP
	case "", "c":
		return languageC
	default:
		log.Printf("Warning: unknown language %q, fallback to C", raw)
		return languageC
	}
}

// readDefinedFunc 从 ELF 文件读取定义的函数符号，忽略未定义项。必要时执行 C++ 解码。
func readDefinedFunc(file string, lang sourceLanguage) ([]SymbolInfo, error) {
	f, err := elf.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 获取符号表
	symbols, err := f.Symbols()
	if err != nil {
		// 如果没有普通符号表，则尝试获取动态符号表
		fmt.Println("Warning: failed to read the static symbol table, trying dynamic symbol table...")
		symbols, err = f.DynamicSymbols()
		if err != nil {
			return nil, err
		}
	}
	var funcs []SymbolInfo
	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Section != elf.SHN_UNDEF {
			demangled := demangleSymbol(sym.Name, lang)
			funcs = append(funcs, SymbolInfo{
				Raw:       sym.Name,
				Demangled: demangled,
			})
		}
	}
	return funcs, nil
}

// ReadConfig 负责读取 YAML 文件并反序列化为 Config。
func ReadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing YAML config: %w", err)
	}

	return &config, nil
}

// shouldIncludeFunc 根据 include/exclude 正则决定函数是否应被 hook。
func shouldIncludeFunc(funcInfo SymbolInfo, includePatterns, excludePatterns PatternRules) bool {
	// First, check include patterns
	// If include patterns are specified, at least one pattern must match
	if len(includePatterns) > 0 {
		includeMatched := false
		for _, pattern := range includePatterns {
			if matchSymbolPattern(pattern, funcInfo) {
				includeMatched = true
				break
			}
		}

		// If function doesn't match any include pattern, skip it
		if !includeMatched {
			return false
		}
	}

	// Second, check exclude patterns
	// If function matches any exclude pattern, skip it
	for _, pattern := range excludePatterns {
		if matchSymbolPattern(pattern, funcInfo) {
			return false
		}
	}

	// Function passed both include and exclude checks
	return true
}

func shouldDemangleSymbol(lang sourceLanguage, name string) bool {
	if lang == languageCPP {
		return true
	}
	// 以 _Z 开头的符号通常为 Itanium C++ ABI 格式。
	return strings.HasPrefix(name, "_Z")
}

// demangleSymbol 首先尝试 Go 内建 demangler，失败时回退到 c++filt，结果会缓存。
func demangleSymbol(name string, lang sourceLanguage) string {
	if !shouldDemangleSymbol(lang, name) {
		return name
	}
	if cached, ok := demangleCache.Load(name); ok {
		return cached.(string)
	}

	demangled := name
	if decoded, err := demangle.ToString(name); err == nil && decoded != "" {
		demangled = decoded
	} else if err != nil {
		log.Printf("Warning: failed to demangle (go) %s: %v", name, err)
	}

	if demangled == name {
		if fromCxxfilt, err := demangleWithCxxfilt(name); err == nil && fromCxxfilt != "" {
			demangled = fromCxxfilt
		} else if err != nil {
			log.Printf("Warning: c++filt demangle failed for %s: %v", name, err)
		}
	}

	demangleCache.Store(name, demangled)
	return demangled
}

func demangleWithCxxfilt(name string) (string, error) {
	cmd := exec.Command("c++filt", name)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, buf.String())
	}
	return strings.TrimSpace(buf.String()), nil
}

// matchSymbolPattern 同时对原始与解码后的符号执行匹配。
func matchSymbolPattern(rule PatternRule, funcInfo SymbolInfo) bool {
	matchScope := strings.ToLower(strings.TrimSpace(rule.Match))
	if matchScope == "" {
		matchScope = "both"
	}

	matchRaw := matchScope == "both" || matchScope == "raw"
	matchDemangled := matchScope == "both" || matchScope == "demangled"

	if matchRaw {
		matched, err := regexp.MatchString(rule.Pattern, funcInfo.Raw)
		if err != nil {
			log.Printf("Warning: Invalid regex pattern '%s': %v", rule.Pattern, err)
		}
		if matched {
			return true
		}
	}

	if matchDemangled && funcInfo.Demangled != "" {
		matched, err := regexp.MatchString(rule.Pattern, funcInfo.Demangled)
		if err != nil {
			log.Printf("Warning: Invalid regex pattern '%s': %v", rule.Pattern, err)
			return false
		}
		return matched
	}

	return false
}
