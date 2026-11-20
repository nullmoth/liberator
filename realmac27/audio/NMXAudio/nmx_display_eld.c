#include "nmx_display_eld.h"

#include <string.h>

#define NMX_ELD_VERSION 2u
#define NMX_ELD_FIXED_BYTES 20u
#define NMX_ELD_MAX_BASELINE_DWORDS 20u /* version 2 supports at most 80 baseline bytes */
#define NMX_ELD_MAX_BYTES 128u
#define NMX_ELD_MAX_MONITOR_NAME 16u
#define NMX_ELD_MAX_SADS 15u
#define NMX_SAD_FORMAT_LPCM 1u
#define NMX_SAD_RATE_48000 (1u << 2)
#define NMX_SAD_SIZE_16BIT (1u << 0)

static bool
nmx_ascii_printable(uint8_t c)
{
    return c >= 0x20u && c <= 0x7eu;
}

static bool
nmx_ascii_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static void
nmx_copy_monitor_name(const uint8_t *src, size_t length, char dst[32])
{
    char filtered[17];
    size_t used = 0;
    size_t first, last, out = 0;

    for (size_t i = 0; i < length && used < sizeof(filtered) - 1; i++) {
        if (nmx_ascii_printable(src[i]))
            filtered[used++] = (char)src[i];
    }
    filtered[used] = '\0';

    first = 0;
    while (first < used && nmx_ascii_space(filtered[first]))
        first++;
    last = used;
    while (last > first && nmx_ascii_space(filtered[last - 1]))
        last--;

    while (first < last && out < 31)
        dst[out++] = filtered[first++];
    dst[out] = '\0';
}

bool
nmx_parse_display_eld(const uint8_t *eld, size_t eld_len,
                      struct nmx_display_endpoint *out)
{
    struct nmx_display_endpoint parsed = {0};
    size_t baseline_end, required_end, sad_offset;
    unsigned version, baseline_dwords, monitor_name_len, sad_count, connector;
    bool supports_engine_format = false;

    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));

    if (eld == NULL || eld_len < NMX_ELD_FIXED_BYTES || eld_len > NMX_ELD_MAX_BYTES)
        return false;

    version = (unsigned)(eld[0] >> 3);
    if (version != NMX_ELD_VERSION)
        return false;

    baseline_dwords = eld[2];
    if (baseline_dwords < 4u || baseline_dwords > NMX_ELD_MAX_BASELINE_DWORDS)
        return false;
    baseline_end = 4u + (size_t)baseline_dwords * 4u;
    if (baseline_end > eld_len)
        return false;

    monitor_name_len = (unsigned)(eld[4] & 0x1fu);
    sad_count = (unsigned)(eld[5] >> 4);
    connector = (unsigned)((eld[5] >> 2) & 0x03u);
    if (monitor_name_len > NMX_ELD_MAX_MONITOR_NAME || sad_count > NMX_ELD_MAX_SADS)
        return false;
    if (connector > 1u)
        return false;

    required_end = NMX_ELD_FIXED_BYTES + (size_t)monitor_name_len + (size_t)sad_count * 3u;
    if (required_end > baseline_end || required_end > eld_len)
        return false;

    sad_offset = NMX_ELD_FIXED_BYTES + monitor_name_len;
    for (unsigned i = 0; i < sad_count; i++) {
        const uint8_t *sad = eld + sad_offset + (size_t)i * 3u;
        unsigned format = (unsigned)((sad[0] >> 3) & 0x0fu);
        unsigned channels = (unsigned)(sad[0] & 0x07u) + 1u;
        bool rate_48000 = (sad[1] & NMX_SAD_RATE_48000) != 0;
        bool size_16bit = (sad[2] & NMX_SAD_SIZE_16BIT) != 0;

        if (format == NMX_SAD_FORMAT_LPCM && channels >= 2u && rate_48000 && size_16bit) {
            supports_engine_format = true;
            break;
        }
    }
    if (!supports_engine_format)
        return false;

    parsed.connector = (uint8_t)connector;
    parsed.manufacturer = (uint16_t)(((uint16_t)eld[16] << 8) | eld[17]);
    parsed.product = (uint16_t)(((uint16_t)eld[19] << 8) | eld[18]);
    nmx_copy_monitor_name(eld + NMX_ELD_FIXED_BYTES, monitor_name_len, parsed.name);
    *out = parsed;
    return true;
}
