#ifndef NMX_DISPLAY_ELD_H
#define NMX_DISPLAY_ELD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct nmx_display_endpoint {
    uint8_t connector;       /* 0 = HDMI, 1 = DisplayPort */
    uint16_t manufacturer;   /* EDID manufacturer ID, in EDID byte order */
    uint16_t product;        /* EDID product code, decoded little-endian */
    char name[32];           /* trimmed printable ASCII; empty when ELD has no usable name */
};

/*
 * Parse a version-2 baseline ELD for the audio format NMXAudio currently opens:
 * stereo LPCM, 48 kHz, 16-bit. The caller must gate this parser on live pin presence.
 * Returns true only for a valid HDMI/DP ELD that advertises that format.
 * On failure, clears `out` so callers cannot accidentally retain a prior sink.
 */
bool nmx_parse_display_eld(const uint8_t *eld, size_t eld_len,
                           struct nmx_display_endpoint *out);

#endif
