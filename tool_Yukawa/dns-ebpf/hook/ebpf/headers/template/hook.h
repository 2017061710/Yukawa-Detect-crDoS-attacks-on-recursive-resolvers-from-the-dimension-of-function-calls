#pragma once
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <template/model.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} func_name_map SEC(".maps");

SEC("uprobe/template")
int template(struct pt_regs *ctx) {
    struct hook_event event = {
        .timestamp_boot_ns = bpf_ktime_get_boot_ns(),
        .tgid_pid = bpf_get_current_pid_tgid(),
        .hook_id = 114,
    };
    bpf_ringbuf_output(&func_name_map, &event, sizeof(event), 0);
    return 0;
}
