#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __always_inline long bpf_probe_read_array(void *dst, __u32 size, const void *src, const int offset) {
    if (size <= 0 || !dst || !src)
        return -1;

    long ret = bpf_probe_read(dst, size, src + offset);
    if (ret < 0)
        return ret;

    return 0;
}
