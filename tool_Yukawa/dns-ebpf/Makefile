# 编译参数
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)

# 路径定义
HOOK_DIR := hook
HOOK_EBPF_DIR := $(HOOK_DIR)/ebpf
HOOK_HEADERS_DIR := $(HOOK_EBPF_DIR)/headers
BPF_OUTPUT_DIR := $(HOOK_DIR)/detail
TARGET_DIR := ./build

# 文件查找
HOOK_HEADERS := $(shell find $(HOOK_HEADERS_DIR) -type f \( -name '*.h' -o -name '*.def.h' \))
HOOK_DEF_FILES := $(shell find $(HOOK_HEADERS_DIR) -type f -name 'hooks.def.h')
HOOK_ID_HEADERS := $(HOOK_DEF_FILES:hooks.def.h=hook_ids.h)
HOOK_SOURCE := $(wildcard $(HOOK_EBPF_DIR)/hook.c)

# 目标定义
BPF_STEM := hook
BPF_TARGET_EL := $(BPF_OUTPUT_DIR)/$(BPF_STEM)_x86_bpfel.o
OBJECT := dns-ebpf
HOOK_PKG := detail

# Go model 相关定义
GO_DEF_DIR := $(HOOK_DIR)/model
GO_DEF_SPECS := $(wildcard $(GO_DEF_DIR)/*_spec.go)
GO_DEF_TARGETS := $(patsubst %_spec.go,%_spec.go.generate,$(GO_DEF_SPECS))

.PHONY: all hook godef clean id

# 默认目标
all: id hook
	@ mkdir -p $(TARGET_DIR)
	@ go build -o $(TARGET_DIR)/$(OBJECT)

hook: $(HOOK_ID_HEADERS) $(BPF_TARGET_EL)

id: $(HOOK_ID_HEADERS)

# 编译 eBPF 字节码并生成 Go 绑定
$(BPF_TARGET_EL): $(HOOK_SOURCE) $(HOOK_HEADERS) $(HOOK_ID_HEADERS)
	@ mkdir -p $(BPF_OUTPUT_DIR)
	@ go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target amd64 \
		-output-stem $(BPF_STEM) -output-dir $(BPF_OUTPUT_DIR) \
		-cc $(BPF_CLANG) -cflags '$(BPF_CFLAGS)' \
		-go-package $(HOOK_PKG) bpf $(HOOK_SOURCE) -- \
		-I$(HOOK_HEADERS_DIR) -I/usr/include/$(shell uname -m)-linux-gnu

# --- 核心修改部分：使用二次展开来处理可选的 manual_hooks.txt ---
.SECONDEXPANSION:

$(HOOK_HEADERS_DIR)/%/hook_ids.h: $(HOOK_HEADERS_DIR)/%/hooks.def.h hook/tools/cmd/hookidgen/main.go $$(wildcard $(HOOK_HEADERS_DIR)/%/manual_hooks.txt)
	@echo "Updating ID header: $@"
	@extra_file="$(dir $@)/manual_hooks.txt"; \
	if [ -f "$$extra_file" ]; then extra_arg="-extra $$extra_file"; else extra_arg=""; fi; \
	go run ./hook/tools/cmd/hookidgen -def $< -o $@ $$extra_arg
# ---------------------------------------------------------

godef: $(GO_DEF_TARGETS)

%_spec.go.generate: %_spec.go
	@ cd $(dir $<) && go tool cgo -godefs $(notdir $<) > $(notdir $@)

clean:
	@ rm -f $(TARGET_DIR)/$(OBJECT)
	@ rm -rf $(BPF_OUTPUT_DIR)
	@ find $(HOOK_HEADERS_DIR) -name "hook_ids.h" -delete