/*
 * The port's sound core, between FreeBSD's HD Audio driver (below, through the channel and mixer classes) and the
 * macOS audio engine (above, nmx_audio_engine.cpp). C, callable from the C++ engine.
 */
#ifndef NMX_PCM_H
#define NMX_PCM_H
#include <stdint.h>
#include "nmx_display_eld.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snddev_info;
struct pcm_channel;

#define NMX_DIR_PLAY 1
#define NMX_DIR_REC  3

enum {
    NMX_DISPLAY_LOCAL,
    NMX_DISPLAY_UNAVAILABLE,
    NMX_DISPLAY_CONNECTED
};

/* HDA pin metadata, copied from each enabled pin's default configuration.
 * Role values intentionally match the HDA default-config device field. */
#define NMX_AUDIO_MAX_PIN_METADATA 32
#define NMX_AUDIO_CODEC_NAME_MAX 64
#define NMX_AUDIO_CHANNEL_LAYOUT_MAX 24

enum {
    NMX_AUDIO_PIN_DIRECTION_UNKNOWN = 0,
    NMX_AUDIO_PIN_DIRECTION_OUTPUT = 1,
    NMX_AUDIO_PIN_DIRECTION_INPUT = 2
};

enum {
    NMX_AUDIO_PIN_DEVICE_LINE_OUT = 0,
    NMX_AUDIO_PIN_DEVICE_SPEAKER = 1,
    NMX_AUDIO_PIN_DEVICE_HEADPHONES = 2,
    NMX_AUDIO_PIN_DEVICE_CD = 3,
    NMX_AUDIO_PIN_DEVICE_SPDIF_OUT = 4,
    NMX_AUDIO_PIN_DEVICE_DIGITAL_OUT = 5,
    NMX_AUDIO_PIN_DEVICE_MODEM_LINE = 6,
    NMX_AUDIO_PIN_DEVICE_MODEM_HANDSET = 7,
    NMX_AUDIO_PIN_DEVICE_LINE_IN = 8,
    NMX_AUDIO_PIN_DEVICE_AUX = 9,
    NMX_AUDIO_PIN_DEVICE_MICROPHONE = 10,
    NMX_AUDIO_PIN_DEVICE_TELEPHONY = 11,
    NMX_AUDIO_PIN_DEVICE_SPDIF_IN = 12,
    NMX_AUDIO_PIN_DEVICE_DIGITAL_IN = 13,
    NMX_AUDIO_PIN_DEVICE_OTHER = 15,
    NMX_AUDIO_PIN_DEVICE_UNKNOWN = 0xff
};

enum {
    NMX_AUDIO_SIGNAL_UNKNOWN = 0,
    NMX_AUDIO_SIGNAL_ANALOG = 1,
    NMX_AUDIO_SIGNAL_DIGITAL = 2,
    NMX_AUDIO_SIGNAL_HDMI = 3,
    NMX_AUDIO_SIGNAL_DISPLAYPORT = 4,
    NMX_AUDIO_SIGNAL_HDMI_DP = 5
};

struct nmx_audio_pin_metadata {
    uint8_t node_id;
    uint8_t direction;
    uint8_t role;
    uint8_t location;
    uint8_t color;
    uint8_t connector;
    uint8_t connectivity;
    uint8_t digital;
    uint8_t association;
    uint8_t sequence;
};

struct nmx_pcm_label_metadata {
    char codec_name[NMX_AUDIO_CODEC_NAME_MAX];
    char channel_layout[NMX_AUDIO_CHANNEL_LAYOUT_MAX];
    uint8_t pin_count;
    struct nmx_audio_pin_metadata pins[NMX_AUDIO_MAX_PIN_METADATA];
    uint8_t direction;
    uint8_t role;
    uint8_t location;
    uint8_t color;
    uint8_t color_is_common;
    uint8_t signal;
};

/* one play or record channel of a PCM device */
int nmx_chan_dir(struct pcm_channel *c);
/* formats the codec accepts (FreeBSD AFMT_* | channel count), 0-terminated; and its rate range */
const uint32_t *nmx_chan_formats(struct pcm_channel *c, uint32_t *minspeed, uint32_t *maxspeed);
int nmx_chan_setformat(struct pcm_channel *c, uint32_t format);
uint32_t nmx_chan_setspeed(struct pcm_channel *c, uint32_t speed);
/* sizes the DMA ring as blkcnt blocks of blksz bytes (an interrupt per block); returns the ring actually used */
int nmx_chan_setfragments(struct pcm_channel *c, uint32_t blksz, uint32_t blkcnt);
void *nmx_chan_ring(struct pcm_channel *c, uint32_t *bytes, uint32_t *blksz);
int nmx_chan_start(struct pcm_channel *c);
int nmx_chan_stop(struct pcm_channel *c);
uint32_t nmx_chan_getptr(struct pcm_channel *c);	/* byte offset in the ring the hardware has reached */
void nmx_chan_set_engine(struct pcm_channel *c, void *engine);
void nmx_chan_clear_engine(struct pcm_channel *c, void *engine);

/* PCM device */
int nmx_pcm_nchan(struct snddev_info *sc);
struct pcm_channel *nmx_pcm_chan(struct snddev_info *sc, int i);
const char *nmx_pcm_name(struct snddev_info *sc);	/* "Realtek ALC897 (Analog)" etc. */
int nmx_pcm_display_endpoint(struct snddev_info *sc, struct nmx_display_endpoint *endpoint);
int nmx_pcm_get_label_metadata(struct snddev_info *sc, int direction,
    struct nmx_pcm_label_metadata *metadata);
/* where the PCM device sits, stable across boots: the controller's PCI address, then the device's position under its
 * codec. Unit numbers are not stable (two controllers attach in parallel), and names repeat (four identical HDMI pins) */
void nmx_pcm_location(struct snddev_info *sc, char *buf, size_t len);
uint32_t nmx_pcm_mixer_devs(struct snddev_info *sc);	/* SOUND_MASK_* the codec has */
int nmx_pcm_mixer_set(struct snddev_info *sc, unsigned dev, unsigned left, unsigned right);	/* 0..100 */

/* the engine side (nmx_audio_engine.cpp) */
void nmx_audio_publish(struct snddev_info *sc);		/* pcm_register: make the IOAudioDevice */
int nmx_audio_unpublish(struct snddev_info *sc);	/* pcm_unregister */
void nmx_audio_block_done(void *engine, struct pcm_channel *c);	/* chn_intr: one DMA block played/recorded */

#ifdef __cplusplus
}
#endif
#endif
