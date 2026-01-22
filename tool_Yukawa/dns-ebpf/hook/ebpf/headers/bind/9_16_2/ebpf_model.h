#pragma once
#include <stdint.h>

#define DNS_NAME_MAX_LENGTH 255
#define DNS_NAME_MAX_LABEL_NUM 128
#define DNS_NAME_MAX_LABEL_LENGTH 63

struct hook_event
{
    uint64_t timestamp_boot_ns;
    uint64_t tgid_pid;
    int32_t hook_id;
    uint16_t transaction_id;
    char name[DNS_NAME_MAX_LENGTH+1];
    uint16_t type;
};
