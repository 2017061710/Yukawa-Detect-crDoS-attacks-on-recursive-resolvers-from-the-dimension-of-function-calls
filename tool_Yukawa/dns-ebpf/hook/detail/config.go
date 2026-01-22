package detail

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// HookPosition 描述 UProbe 附加在目标函数的哪个位置，目前仅支持 entry/return。
type HookPosition string

const (
	HookPositionEntry  HookPosition = "entry"
	HookPositionReturn HookPosition = "return"
)

// Program 描述一个需要按名称加载并附着到目标二进制的 uprobe。
type Program struct {
	Name     string `yaml:"name"`
	BinPath  string `yaml:"bin_path"`
	Symbol   string `yaml:"symbol"`
	Position string `yaml:"position"`
}

// MapSpec 用于声明需要从 eBPF 集合里加载的 map，名称需与 bpf2go 生成的 `ebpf` 标签一致。
type MapSpec struct {
	Name string `yaml:"name"`
}

// Config 汇总 detail 模式运行所需的全部信息，由 YAML 配置提供。
type Config struct {
	Programs     []Program           `yaml:"programs"`
	Maps         []MapSpec           `yaml:"maps"`
	Infos        []map[string]string `yaml:"infos"`
	EventDecoder string              `yaml:"event_decoder"`
}

// ReadConfig 读取并解析 detail 模式配置。
func ReadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing YAML config: %w", err)
	}

	return &config, nil
}

// DecoderName 返回配置的解码器名称，若为空则退回默认 BIND 解码器。
func (c *Config) DecoderName() string {
	if c.EventDecoder == "" {
		return defaultEventDecoderName
	}
	return c.EventDecoder
}
