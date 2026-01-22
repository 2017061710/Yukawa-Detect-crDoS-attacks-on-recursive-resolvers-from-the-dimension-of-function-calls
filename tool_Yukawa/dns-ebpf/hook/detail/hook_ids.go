package detail

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var hookIDPattern = regexp.MustCompile(`^#define\s+(HOOK_[A-Za-z0-9_]+)\s+(\d+)`)

// ParseHookIDMap 解析 hook_ids.h 文件，返回 Hook ID 到名称的映射；该函数会跳过注释和空行，兼容自动或手工编辑的头文件。
func ParseHookIDMap(headerPath string) (map[int32]string, error) {
	file, err := os.Open(headerPath)
	if err != nil {
		return nil, fmt.Errorf("open hook id file: %w", err)
	}
	defer file.Close()

	hookMap := make(map[int32]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		matches := hookIDPattern.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		id, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("parse hook id %q: %w", matches[2], err)
		}
		hookMap[int32(id)] = matches[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan hook id file: %w", err)
	}
	return hookMap, nil
}
