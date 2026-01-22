#pragma once
#include <stdint.h>

struct hook_event
{
    uint64_t timestamp_boot_ns;
    uint64_t tgid_pid;
    int32_t hook_id;
};