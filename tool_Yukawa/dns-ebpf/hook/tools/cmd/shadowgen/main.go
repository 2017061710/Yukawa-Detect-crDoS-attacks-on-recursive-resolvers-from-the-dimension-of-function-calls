package main

import (
	"debug/dwarf"
	"debug/elf"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

type Field struct {
	Name   string
	Offset int64
	Size   int64
	Type   string
}

// 全局配置，由命令行参数决定
var (
	doTranslate bool
)

func main() {
	elfPath := flag.String("file", "", "目标 ELF 文件路径")
	structName := flag.String("struct", "", "目标结构体名称")
	keepFields := flag.String("fields", "", "保留字段名 (逗号分隔)")
	// 添加 translate 参数，默认为 false
	flag.BoolVar(&doTranslate, "translate", false, "是否将原始 C 类型转换为 uintN_t 风格")
	flag.Parse()

	if *elfPath == "" || *structName == "" {
		flag.Usage()
		os.Exit(1)
	}

	filter := make(map[string]bool)
	if *keepFields != "" {
		for _, f := range strings.Split(*keepFields, ",") {
			filter[strings.TrimSpace(f)] = true
		}
	}

	f, err := elf.Open(*elfPath)
	if err != nil {
		log.Fatalf("无法打开 ELF: %v", err)
	}
	defer f.Close()

	d, err := f.DWARF()
	if err != nil {
		log.Fatalf("无法读取 DWARF: %v", err)
	}

	entry, err := findStructEntry(d, *structName)
	if err != nil {
		log.Fatalf("错误: %v", err)
	}

	totalSize, _ := entry.Val(dwarf.AttrByteSize).(int64)
	fields, err := parseMembers(d, entry)
	if err != nil {
		log.Fatalf("解析成员失败: %v", err)
	}

	generateC(*structName, totalSize, fields, filter)
}

func findStructEntry(d *dwarf.Data, name string) (*dwarf.Entry, error) {
	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if entry == nil || err != nil {
			break
		}
		if entry.Tag == dwarf.TagStructType {
			if n, ok := entry.Val(dwarf.AttrName).(string); ok && n == name {
				return entry, nil
			}
		}
	}
	return nil, fmt.Errorf("未找到结构体: %s", name)
}

func parseMembers(d *dwarf.Data, parent *dwarf.Entry) ([]Field, error) {
	var fields []Field
	reader := d.Reader()
	reader.Seek(parent.Offset)
	reader.Next()

	for {
		entry, err := reader.Next()
		if entry == nil || entry.Tag == 0 || err != nil {
			break
		}

		if entry.Tag == dwarf.TagMember {
			name, _ := entry.Val(dwarf.AttrName).(string)
			offset, _ := entry.Val(dwarf.AttrDataMemberLoc).(int64)
			typeOff, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)

			typ, err := d.Type(typeOff)
			if err != nil {
				continue
			}

			fields = append(fields, Field{
				Name:   name,
				Offset: offset,
				Size:   typ.Size(),
				Type:   formatCType(typ),
			})
		} else {
			if entry.Children {
				reader.SkipChildren()
			}
		}
	}
	return fields, nil
}

func formatCType(typ dwarf.Type) string {
	switch t := typ.(type) {
	case *dwarf.PtrType:
		// 递归获取指针指向的类型名
		if t.Type != nil {
			subType := formatCType(t.Type)
			// 处理一些特殊情况，比如指向函数的指针或复杂的嵌套
			if strings.HasSuffix(subType, "*") || subType == "void" {
				return subType + "*"
			}
			return subType + "*"
		}
		return "void*"

	case *dwarf.ArrayType:
		return fmt.Sprintf("%s[%d]", formatCType(t.Type), t.Count)

	case *dwarf.StructType:
		prefix := t.Kind
		if t.StructName == "" {
			return prefix + " { /* anonymous */ }"
		}
		// 如果是 struct XXX，确保带上 struct 关键字
		if !strings.HasPrefix(t.StructName, "struct ") && !strings.HasPrefix(t.StructName, "union ") {
			return prefix + " " + t.StructName
		}
		return t.StructName

	case *dwarf.TypedefType:
		// 优先返回用户定义的类型名 (如 uint8_t)
		return t.Name

	case *dwarf.BasicType:
		if doTranslate {
			return translateBasicType(t.Name, t.Size())
		}
		return t.Name

	default:
		return "uint8_t"
	}
}

func translateBasicType(name string, size int64) string {
	switch size {
	case 1:
		return "uint8_t"
	case 2:
		return "uint16_t"
	case 4:
		return "uint32_t"
	case 8:
		return "uint64_t"
	default:
		return name
	}
}

func generateC(name string, totalSize int64, fields []Field, filter map[string]bool) {
	fmt.Printf("/* Generated Shadow Struct for %s */\n", name)
	fmt.Printf("#include <stdint.h>\n")
	fmt.Printf("#include <stddef.h>\n\n")
	fmt.Printf("struct %s_shadow {\n", name)

	var currentOffset int64 = 0
	padIdx := 0

	for _, f := range fields {
		if f.Offset > currentOffset {
			fmt.Printf("    uint8_t __pad_%d[%d];\n", padIdx, f.Offset-currentOffset)
			padIdx++
		}

		shouldKeep := len(filter) == 0 || filter[f.Name]

		if shouldKeep && f.Name != "" {
			if strings.Contains(f.Type, "[") {
				parts := strings.SplitN(f.Type, "[", 2)
				fmt.Printf("    %s %s[%s; // offset: %d\n", parts[0], f.Name, parts[1], f.Offset)
			} else {
				fmt.Printf("    %s %s; // offset: %d\n", f.Type, f.Name, f.Offset)
			}
			currentOffset = f.Offset + f.Size
		} else {
			size := f.Size
			if size > 0 {
				fmt.Printf("    uint8_t __pad_%d[%d]; // skip %s\n", padIdx, size, f.Name)
				padIdx++
				currentOffset = f.Offset + size
			}
		}
	}

	if currentOffset < totalSize {
		fmt.Printf("    uint8_t __pad_%d[%d];\n", padIdx, totalSize-currentOffset)
	}

	fmt.Printf("};\n")
}
