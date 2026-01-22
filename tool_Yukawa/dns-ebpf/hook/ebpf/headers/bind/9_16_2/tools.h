#pragma once
#include <bind/9_16_2/model.h>
#include <common/tools.h>

#define DNS_NAME_TO_TEXT_ERROR_BADNAME -1
#define DNS_NAME_TO_TEXT_ERROR_BADBUFFER -2
#define DNS_NAME_TO_TEXT_ERROR_NOSPACE -3
#define DNS_NAME_TO_TEXT_ERROR_READFAIL -4
/**
 * 参考自 isc_result_t dns_name_totext2(const dns_name_t *name, unsigned int options, isc_buffer_t *target)
 * 注意： name 已经在 eBPF 程序栈上，可以直接读取，否则，请使用 bpf_dns_name_to_text_safe_nostack
 * 返回：
 *  正值：转换后的字符串长度（其中，空域名 "@"长度为1）
 *  负值：错误码
 */
static __always_inline int bpf_dns_name_to_text(const struct dns_name *name, char *buf, int buf_len)
{
    if (!name || !name->ndata)
        return DNS_NAME_TO_TEXT_ERROR_BADNAME;
    if (!buf || buf_len <= 0)
        return DNS_NAME_TO_TEXT_ERROR_BADBUFFER;

    unsigned char *ndata = name->ndata;
    int buf_idx = 0;
    int offset = 0;
    char tmp_char;

    if (name->labels == 0 && name->length == 0)
    {
        if (buf_idx >= buf_len - 1)
            return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
        buf[buf_idx++] = '@';
        return buf_idx;
    } else if (name->labels==1 && name->length==1) {
        if (bpf_probe_read_array(&tmp_char, sizeof(tmp_char), ndata, offset) < 0)
            return DNS_NAME_TO_TEXT_ERROR_READFAIL;
        if (tmp_char == '\0'){
            buf[buf_idx++] = '.';
            return buf_idx;
        }
    }

    int label_idx = 0;
    bpf_for(label_idx, 0, DNS_NAME_MAX_LABEL_NUM)
    {   
        if (offset >= name->length)
            break;
        if (buf_idx >= buf_len - 1)
            return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
        if (bpf_probe_read_array(&tmp_char, sizeof(tmp_char), ndata, offset) < 0)
            return DNS_NAME_TO_TEXT_ERROR_READFAIL;
        unsigned char label_len = tmp_char;
        if (label_len == 0)
        {
            break; // 域名结束
        }
        // 最长标签长度63，并确保不会越界
        if (label_len > DNS_NAME_MAX_LABEL_LENGTH || offset + 1 + label_len > name->length)
            return DNS_NAME_TO_TEXT_ERROR_BADNAME;
        int i = 0;
        // label最大长度63
        bpf_for(i, 0, DNS_NAME_MAX_LABEL_LENGTH)
        { 
            if (i >= label_len)
                break;
            if (buf_idx >= buf_len - 1)
                return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
            if (bpf_probe_read_array(&tmp_char, sizeof(tmp_char), ndata, offset + 1 + i) < 0)
                return DNS_NAME_TO_TEXT_ERROR_READFAIL;
            char c = tmp_char;
            // TODO: 这里没有处理转义字符（不过不影响）
            buf[buf_idx++] = c;
        }
        // 更新offset
        offset += 1 + label_len;
        if (buf_idx >= buf_len - 1)
            return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
        buf[buf_idx++] = '.';
    }

    buf[buf_idx] = '\0';
    return buf_idx;
}

/**
 * 参考自 isc_result_t dns_name_totext2(const dns_name_t *name, unsigned int options, isc_buffer_t *target)
 * 直接读取用户空间指针，避免全部复制到栈上，导致eBPF栈空间不足
 * 返回：
 *  正值：转换后的字符串长度（其中，空域名 "@"长度为1）
 *  负值：错误码
 */
static __always_inline int bpf_dns_name_to_text_safe_nostack(const struct dns_name *name_ptr, char *buf, int buf_len)
{
    if (!name_ptr || !buf || buf_len <= 0)
        return DNS_NAME_TO_TEXT_ERROR_BADBUFFER;

    unsigned char *ndata_ptr = NULL;
    unsigned int labels = 0, length = 0;
    unsigned char tmp_char = 0;
    int buf_idx = 0, offset = 0;

    // === 1. 读取基础字段 ===
    if (bpf_probe_read(&labels, sizeof(labels), &name_ptr->labels) < 0)
        return DNS_NAME_TO_TEXT_ERROR_READFAIL;
    if (bpf_probe_read(&length, sizeof(length), &name_ptr->length) < 0)
        return DNS_NAME_TO_TEXT_ERROR_READFAIL;
    if (bpf_probe_read(&ndata_ptr, sizeof(ndata_ptr), &name_ptr->ndata) < 0)
        return DNS_NAME_TO_TEXT_ERROR_READFAIL;

    if (!ndata_ptr)
        return DNS_NAME_TO_TEXT_ERROR_BADNAME;

    // === 2. 特殊情况处理：根域名 ===
    if (labels == 0 && length == 0) {
        if (buf_len < 2)
            return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
        buf[0] = '@';
        buf[1] = '\0';
        return 1;
    } else if (labels == 1 && length == 1) {
        if (bpf_probe_read(&tmp_char, sizeof(tmp_char), ndata_ptr) < 0)
            return DNS_NAME_TO_TEXT_ERROR_READFAIL;
        if (tmp_char == '\0') {
            if (buf_len < 2)
                return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
            buf[0] = '.';
            buf[1] = '\0';
            return 1;
        }
    }

    // === 3. 遍历 label ===
    int label_idx = 0;
    bpf_for(label_idx, 0, DNS_NAME_MAX_LABEL_NUM) {
        if (offset >= length)
            break;

        // 读取当前 label 长度
        if (bpf_probe_read(&tmp_char, sizeof(tmp_char), ndata_ptr + offset) < 0)
            return DNS_NAME_TO_TEXT_ERROR_READFAIL;
        unsigned char label_len = tmp_char;

        if (label_len == 0)
            break; // 域名结束
        if (label_len > DNS_NAME_MAX_LABEL_LENGTH || offset + 1 + label_len > length)
            return DNS_NAME_TO_TEXT_ERROR_BADNAME;

        // === 4. 读取每个 label 字符 ===
        int i = 0;
        bpf_for(i, 0, DNS_NAME_MAX_LABEL_LENGTH) {
            if (i >= label_len)
                break;
            if (buf_idx >= buf_len - 1)
                return DNS_NAME_TO_TEXT_ERROR_NOSPACE;

            if (bpf_probe_read(&tmp_char, sizeof(tmp_char), ndata_ptr + offset + 1 + i) < 0)
                return DNS_NAME_TO_TEXT_ERROR_READFAIL;

            buf[buf_idx++] = (char)tmp_char;
        }

        // === 5. 加上'.'分隔符 ===
        if (buf_idx >= buf_len - 1)
            return DNS_NAME_TO_TEXT_ERROR_NOSPACE;
        buf[buf_idx++] = '.';

        offset += 1 + label_len;
    }

    // === 6. 结束符 ===
    if (buf_idx < buf_len)
        buf[buf_idx] = '\0';
    else
        buf[buf_len - 1] = '\0';

    return buf_idx;
}
