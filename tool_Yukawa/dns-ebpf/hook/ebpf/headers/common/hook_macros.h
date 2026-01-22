#pragma once

#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* -------------------------------------------------------------------------- */
/*                      Shared helpers for ebpf hook code                     */
/* -------------------------------------------------------------------------- */

// Simplified safe read helper that bails out of the current hook on failure.
#define HOOK_READ_ONCE(dst, src)                              \
    ({                                                        \
        typeof(*(src)) __tmp;                                 \
        if (bpf_probe_read(&__tmp, sizeof(__tmp), src) < 0) { \
            return 0;                                         \
        }                                                     \
        dst = __tmp;                                          \
    })

// Accessors for uprobes arguments with explicit pointer semantics.
#define HOOK_PARAM(type, idx) ((type)PT_REGS_PARM##idx(ctx))
#define HOOK_PARAM_PTR(type, idx) ((type *)PT_REGS_PARM##idx(ctx))
#define HOOK_PARAM_PTR_PTR(type, idx)                               \
    ({                                                              \
        type **tmp = (type **)PT_REGS_PARM##idx(ctx);               \
        type *val = NULL;                                           \
        if (tmp) {                                                  \
            HOOK_READ_ONCE(val, tmp);                               \
        }                                                           \
        val;                                                        \
    })

// Typed uprobes wrapper to reduce boilerplate.
#define HOOK_TYPED_UPROBE(target, param_type, expr, reporter) \
    SEC("uprobe/" #target)                                   \
    int uprobe_##target(struct pt_regs *ctx)                 \
    {                                                       \
        param_type *param = expr;                           \
        return reporter(ctx, param, HOOK_uprobe_##target);  \
    }
