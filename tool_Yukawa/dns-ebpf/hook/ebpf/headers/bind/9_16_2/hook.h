#pragma once

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <common/hook_macros.h>
#include <bind/9_16_2/model.h>
#include <bind/9_16_2/ebpf_model.h>
#include <bind/9_16_2/tools.h>
#include <bind/9_16_2/hook_ids.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} hook_event_map SEC(".maps");

/* -------------------------------------------------------------------------- */
/*                               公共工具函数                                  */
/* -------------------------------------------------------------------------- */

// 通用解析函数：提取 Question Section 的第一个域名和类型并输出事件
static __always_inline int
report_dns_message_event(void *ctx, dns_message_t *msg, int hook_id)
{
    if (!msg)
        return 0;

    dns_namelist_t *question_section_ptr = &msg->sections[DNS_SECTION_QUESTION];
    dns_namelist_t question_section;
    if (bpf_probe_read(&question_section, sizeof(question_section), question_section_ptr) < 0)
        return 0;
    if (question_section.head == NULL)
        return 0;

    dns_name_t *dns_name_0_ptr = NULL;
    HOOK_READ_ONCE(dns_name_0_ptr, &question_section.head);
    if (!dns_name_0_ptr)
        return 0;

    dns_rdataset_t *rdataset_head_ptr = NULL;
    HOOK_READ_ONCE(rdataset_head_ptr, &dns_name_0_ptr->list.head);
    if (!rdataset_head_ptr)
        return 0;

    dns_rdataset_t rdataset;
    if (bpf_probe_read(&rdataset, sizeof(rdataset), rdataset_head_ptr) < 0)
        return 0;

    struct hook_event event = {
        .timestamp_boot_ns = bpf_ktime_get_boot_ns(),
        .tgid_pid = bpf_get_current_pid_tgid(),
        .hook_id = hook_id,
        .name = {'\0'},
        .type = rdataset.type,
    };
    HOOK_READ_ONCE(event.transaction_id, &msg->id);
    bpf_dns_name_to_text_safe_nostack(dns_name_0_ptr, event.name, sizeof(event.name));
    bpf_ringbuf_output(&hook_event_map, &event, sizeof(event), 0);
    return 0;
}

static __always_inline int
report_fetchctx_event(void *ctx, fetchctx_t *fctx, int hook_id)
{
    if (!fctx)
        return 0;

    struct hook_event event = {
        .timestamp_boot_ns = bpf_ktime_get_boot_ns(),
        .tgid_pid = bpf_get_current_pid_tgid(),
        .hook_id = hook_id,
        .name = {'\0'},
    };

    bpf_dns_name_to_text_safe_nostack(&fctx->name, event.name, sizeof(event.name));
    HOOK_READ_ONCE(event.type, &fctx->type);
    HOOK_READ_ONCE(event.transaction_id, &fctx->id);
    bpf_ringbuf_output(&hook_event_map, &event, sizeof(event), 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                              手动 Hook 函数                                 */
/* -------------------------------------------------------------------------- */



/* -------------------------------------------------------------------------- */
/*                      Hook 模板宏（可扩展新的类型）                           */
/* -------------------------------------------------------------------------- */

/*
 * 通用模板说明：
 *  1. 定义一个 report_xxx_event(ctx, ptr, hook_id) 函数，用于序列化该类型的输出。
 *  2. 使用 HOOK_PARAM/HOOK_PARAM_PTR/HOOK_PARAM_PTR_PTR 声明参数读取宏（示例：DNS_MSG_PARAM）。
 *  3. 使用 HOOK_TYPED_UPROBE(target, type, expr, reporter) 快速生成宏（示例：DNS_MSG_HOOK）。
 *
 * 这样可以方便扩展新的类型，例如 fetchctx_t、dns_message_t、dns_request_t 等。
 */

#define DNS_MSG_PARAM_PTR(idx) HOOK_PARAM_PTR(dns_message_t, idx)
#define DNS_MSG_PARAM_PTR_PTR(idx) HOOK_PARAM_PTR_PTR(dns_message_t, idx)
#define DNS_MSG_HOOK(target, expr) \
    HOOK_TYPED_UPROBE(target, dns_message_t, expr, report_dns_message_event)

/* fetchctx_t + 通用事件提取 */
#define FETCHCTX_PARAM_PTR(idx) HOOK_PARAM_PTR(fetchctx_t, idx)
#define FETCHCTX_PARAM_PTR_PTR(idx) HOOK_PARAM_PTR_PTR(fetchctx_t, idx)
#define FETCHCTX_HOOK(target, expr) \
    HOOK_TYPED_UPROBE(target, fetchctx_t, expr, report_fetchctx_event)

#include <bind/9_16_2/hooks.def.h>

#undef FETCHCTX_PARAM_PTR
#undef FETCHCTX_PARAM_PTR_PTR
#undef FETCHCTX_HOOK

#undef DNS_MSG_PARAM_PTR
#undef DNS_MSG_PARAM_PTR_PTR
#undef DNS_MSG_PARAM
