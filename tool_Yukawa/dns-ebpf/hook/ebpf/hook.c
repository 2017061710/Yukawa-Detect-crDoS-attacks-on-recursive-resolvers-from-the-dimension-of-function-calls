//go:build ignore
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 许可证
char __license[] SEC("license") = "Dual MIT/GPL";

// 宏定义区
// #define TEMPLATE
#define BIND_9_16_2

// 函数定义区
#ifdef TEMPLATE
#include "headers/template/hook.h"
#endif

#ifdef BIND_9_16_2
#include "headers/bind/9_16_2/hook.h"
#endif