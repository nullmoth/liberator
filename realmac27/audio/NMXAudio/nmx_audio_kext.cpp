/*
 * NMXAudio: HD Audio for macOS 26, which no longer ships AppleHDA. Without it a PC's onboard codec and its graphics
 * card's HDMI/DisplayPort audio have no driver, macOS has no audio device at all, and media playback fails with it -
 * Safari's player reports a decode error for any video with sound (YouTube shows a black frame), because AVFoundation's
 * audio renderer finds no output.
 *
 * Below: FreeBSD's HD Audio driver (hdac controller, hdacc codec, hdaa function group with its generic widget parser,
 * pin quirks and HDMI/DP ELD handling) on the port's FreeBSD-on-xnu layer, unchanged, through the port's sound core
 * (nmx_pcm.c). Above: one IOAudioDevice per PCM device hdaa creates ("Realtek ALC897 (Analog)", "NVIDIA (HDMI/DP 8ch)"),
 * each with an output engine and, where the codec records, an input engine. The engines play and record straight from
 * the DMA ring the controller runs; CoreAudio mixes and converts into it.
 *
 * Matches every PCI HD Audio controller (class 04:03). Only on macOS 26 and later unless the boot argument nmxaudio=1
 * is set: on macOS 15 AppleHDA drives these. -nvoff parks it like every NullMoth driver; nmxaudio=0 turns it off.
 */
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IONVRAM.h>
#include <libkern/c++/OSData.h>
#include <IOKit/audio/IOAudioDevice.h>
#include <IOKit/audio/IOAudioEngine.h>
#include <IOKit/audio/IOAudioStream.h>
#include <IOKit/audio/IOAudioLevelControl.h>
#include <IOKit/audio/IOAudioToggleControl.h>
#include <IOKit/audio/IOAudioDefines.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/version.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include <sys/errno.h>
#include <kern/thread.h>
#include "nmx_port.h"
#include "nmx_pcm.h"
#include "nmx_audio_locale.h"
#include "nmx_display_gain.h"

/* FreeBSD's format and mixer constants the engine needs (sys/soundcard.h); the C side owns everything else */
#define NMX_AFMT_S16_LE 0x00000010
#define NMX_AFMT_S32_LE 0x00001000
#define NMX_FMT(f, ch) ((f) | ((uint32_t)(ch) << 20))
#define NMX_MIXER_VOLUME 0
#define NMX_MIXER_PCM 4
#define NMX_MIXER_RECLEV 11

extern "C" {
struct nmx_drvmod { const char *bus; void *driver; };
extern struct nmx_drvmod nmx_drvmod_snd_hda_pci, nmx_drvmod_snd_hda_hdac, nmx_drvmod_snd_hda_hdacc,
    nmx_drvmod_snd_hda_pcm_hdaa;
void *devclass_create(const char *name);
int devclass_add_driver(void *dc, void *driver, int pass, void **dcp);
}

static NMXAudioLocaleCode g_locale = NMX_AUDIO_LOCALE_EN;

static const char *audioText(const char *key)
{
    return nmxAudioText(g_locale, key);
}

static const char *pcmRoleText(uint8_t role)
{
    switch (role) {
    case NMX_AUDIO_PIN_DEVICE_LINE_OUT: return audioText(NMX_AUDIO_TEXT_LINE_OUT);
    case NMX_AUDIO_PIN_DEVICE_SPEAKER: return audioText("speaker");
    case NMX_AUDIO_PIN_DEVICE_HEADPHONES: return audioText(NMX_AUDIO_TEXT_HEADPHONES);
    case NMX_AUDIO_PIN_DEVICE_CD: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_CD);
    case NMX_AUDIO_PIN_DEVICE_SPDIF_OUT: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_OUT);
    case NMX_AUDIO_PIN_DEVICE_DIGITAL_OUT: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_OUT);
    case NMX_AUDIO_PIN_DEVICE_MODEM_LINE: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_MODEM_LINE);
    case NMX_AUDIO_PIN_DEVICE_MODEM_HANDSET: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_MODEM_HANDSET);
    case NMX_AUDIO_PIN_DEVICE_LINE_IN: return audioText(NMX_AUDIO_TEXT_LINE_IN);
    case NMX_AUDIO_PIN_DEVICE_AUX: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_AUX);
    case NMX_AUDIO_PIN_DEVICE_MICROPHONE: return audioText(NMX_AUDIO_TEXT_MICROPHONE);
    case NMX_AUDIO_PIN_DEVICE_TELEPHONY: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_TELEPHONY);
    case NMX_AUDIO_PIN_DEVICE_SPDIF_IN: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_IN);
    case NMX_AUDIO_PIN_DEVICE_DIGITAL_IN: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_IN);
    case NMX_AUDIO_PIN_DEVICE_OTHER: return audioText(NMX_AUDIO_TEXT_PIN_ROLE_OTHER);
    default: return nullptr;
    }
}

static const char *pcmLocationText(uint8_t location)
{
    switch (location) {
    case 1: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_REAR);
    case 2: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_FRONT);
    case 3: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_LEFT);
    case 4: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_RIGHT);
    case 5: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_TOP);
    case 6: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_BOTTOM);
    case 7: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_REAR_PANEL);
    case 8: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_DRIVE_BAY);
    case 16: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_INTERNAL);
    case 23: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_RISER);
    case 25: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_ONBOARD);
    case 32: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXTERNAL);
    case 33: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_REAR);
    case 34: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_FRONT);
    case 35: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_LEFT);
    case 36: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_RIGHT);
    case 37: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_TOP);
    case 38: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_EXT_BOTTOM);
    case 48: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_OTHER);
    case 55: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_OTHER_BOTTOM);
    case 56: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_LID_IN);
    case 57: return audioText(NMX_AUDIO_TEXT_PIN_LOCATION_LID_OUT);
    default: return nullptr;
    }
}

static const char *pcmSignalText(uint8_t signal)
{
    switch (signal) {
    case NMX_AUDIO_SIGNAL_ANALOG: return audioText(NMX_AUDIO_TEXT_PIN_SIGNAL_ANALOG);
    case NMX_AUDIO_SIGNAL_DIGITAL: return audioText(NMX_AUDIO_TEXT_PIN_SIGNAL_DIGITAL);
    case NMX_AUDIO_SIGNAL_HDMI: return audioText(NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI);
    case NMX_AUDIO_SIGNAL_DISPLAYPORT: return audioText(NMX_AUDIO_TEXT_PIN_SIGNAL_DISPLAYPORT);
    case NMX_AUDIO_SIGNAL_HDMI_DP: return audioText(NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI_DP);
    default: return nullptr;
    }
}

static const char *pcmDirectionText(uint8_t direction)
{
    switch (direction) {
    case NMX_AUDIO_PIN_DIRECTION_INPUT: return audioText(NMX_AUDIO_TEXT_PIN_DIRECTION_INPUT);
    case NMX_AUDIO_PIN_DIRECTION_OUTPUT: return audioText(NMX_AUDIO_TEXT_PIN_DIRECTION_OUTPUT);
    default: return nullptr;
    }
}

static const char *pcmColorText(uint8_t color)
{
    switch (color) {
    case 1: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_BLACK);
    case 2: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_GRAY);
    case 3: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_BLUE);
    case 4: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_GREEN);
    case 5: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_RED);
    case 6: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_ORANGE);
    case 7: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_YELLOW);
    case 8: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_PURPLE);
    case 9: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_PINK);
    case 14: return audioText(NMX_AUDIO_TEXT_PIN_COLOR_WHITE);
    default: return nullptr;
    }
}

static const char *pcmLabel(struct snddev_info *pcm, int direction,
    char *buffer, size_t capacity)
{
    struct nmx_pcm_label_metadata metadata = {};
    if (!nmx_pcm_get_label_metadata(pcm, direction, &metadata))
        return nmx_pcm_name(pcm);

    const char *role = pcmRoleText(metadata.role);
    const char *signal = role ? nullptr : pcmSignalText(metadata.signal);
    const char *location = pcmLocationText(metadata.location);
    const char *directionText = role ? nullptr : pcmDirectionText(metadata.direction);
    const char *color = metadata.color_is_common ? pcmColorText(metadata.color) : nullptr;
    char port[96] = {};
    const char *portName = nmxAudioFormatPortName(g_locale, location,
        role ? role : signal, directionText, port, sizeof(port)) ? port : nullptr;
    if (!portName && !color && !metadata.channel_layout[0])
        return nmx_pcm_name(pcm);
    if (!nmxAudioFormatPCMName(g_locale, metadata.codec_name, portName, color,
        metadata.channel_layout, buffer, capacity))
        return nmx_pcm_name(pcm);
    return buffer;
}

static void setPinNumber(OSDictionary *entry, const char *key, uint8_t value)
{
    OSNumber *number = OSNumber::withNumber(value, 8);
    if (number) {
        entry->setObject(key, number);
        number->release();
    }
}

static void publishPinMetadata(IOAudioDevice *device,
    const struct nmx_pcm_label_metadata *metadata)
{
    if (!device || !metadata || metadata->pin_count == 0)
        return;
    OSArray *pins = OSArray::withCapacity(metadata->pin_count);
    if (!pins)
        return;
    for (UInt32 i = 0; i < metadata->pin_count; ++i) {
        const struct nmx_audio_pin_metadata &pin = metadata->pins[i];
        OSDictionary *entry = OSDictionary::withCapacity(10);
        if (!entry)
            break;
        setPinNumber(entry, "NodeID", pin.node_id);
        setPinNumber(entry, "Direction", pin.direction);
        setPinNumber(entry, "Role", pin.role);
        setPinNumber(entry, "Location", pin.location);
        setPinNumber(entry, "Color", pin.color);
        setPinNumber(entry, "Connector", pin.connector);
        setPinNumber(entry, "Connectivity", pin.connectivity);
        setPinNumber(entry, "Digital", pin.digital);
        setPinNumber(entry, "Association", pin.association);
        setPinNumber(entry, "Sequence", pin.sequence);
        pins->setObject(entry);
        entry->release();
    }
    device->setProperty("NMXAudioPinMetadata", pins);
    pins->release();
}


/* ---- the engine: one channel (play or record) of one PCM device */

class NMXAudioEngine : public IOAudioEngine {
    OSDeclareDefaultStructors(NMXAudioEngine)
    struct snddev_info *sc_;
    struct pcm_channel *ch_;
    bool output_;
    const char *displayName_ = nullptr;
    char pcmLabel_[192] = {};
    void *ring_;
    UInt32 ringBytes_, frameBytes_, frames_, lastPtr_;
    UInt32 sampleBits_;
    IOAudioStream *stream_;
    bool started_;
    static IOReturn volumeChanged(OSObject *target, IOAudioControl *, SInt32, SInt32 v);
    static IOReturn muteChanged(OSObject *target, IOAudioControl *, SInt32, SInt32 v);
    SInt32 volume_ = 75;
    bool muted_ = false;
    UInt32 displayLevels_ = 0x00006464; // left, right; bit 16 is mute
    void setDisplayLevel(UInt32 shift, UInt32 mask, UInt32 level);
    void detachChannel();
public:
    bool initFor(struct snddev_info *sc, struct pcm_channel *ch, const char *displayName);
    bool initHardware(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    UInt32 getCurrentSampleFrame() override;
    IOReturn performAudioEngineStart() override;
    IOReturn performAudioEngineStop() override;
    IOReturn performFormatChange(IOAudioStream *, const IOAudioStreamFormat *, const IOAudioSampleRate *) override;
    IOReturn clipOutputSamples(const void *mixBuf, void *sampleBuf, UInt32 firstSampleFrame, UInt32 numSampleFrames,
                               const IOAudioStreamFormat *streamFormat, IOAudioStream *audioStream) override;
    IOReturn convertInputSamples(const void *sampleBuf, void *destBuf, UInt32 firstSampleFrame, UInt32 numSampleFrames,
                                 const IOAudioStreamFormat *streamFormat, IOAudioStream *audioStream) override;
    void blockDone();
    OSString *getGlobalUniqueID() override;
};
OSDefineMetaClassAndStructors(NMXAudioEngine, IOAudioEngine)

// CoreAudio keys a device by this ID, so it must differ per engine and survive reboots (saved volume and default
// device follow it). IOAudioEngine's own is "<class>:<index on the device>", the same for every PCM device, and
// CoreAudio kept only the last engine it saw with each ID: one of six outputs showed up.
OSString *NMXAudioEngine::getGlobalUniqueID()
{
    char loc[48], id[96];
    nmx_pcm_location(sc_, loc, sizeof(loc));
    snprintf(id, sizeof(id), "NMXAudio:%s:%s", loc, output_ ? "out" : "in");
    return OSString::withCString(id);
}

bool NMXAudioEngine::initFor(struct snddev_info *sc, struct pcm_channel *ch, const char *displayName)
{
    if (!IOAudioEngine::init(nullptr))
        return false;
    sc_ = sc;
    ch_ = ch;
    output_ = nmx_chan_dir(ch) == NMX_DIR_PLAY;
    displayName_ = output_ ? displayName : nullptr;
    return true;
}

/*
 * Format: stereo at 48 kHz (44.1 kHz too when the codec has it), 32-bit samples when the codec takes them (hdaa sends
 * 20/24/32 significant bits from a 32-bit container) and 16-bit otherwise. Every HD Audio codec and HDMI sink has 48 kHz
 * stereo 16-bit; CoreAudio converts the rest.
 */
bool NMXAudioEngine::initHardware(IOService *provider)
{
    if (!IOAudioEngine::initHardware(provider))
        return false;
    uint32_t minspeed = 0, maxspeed = 0;
    const uint32_t *fmts = nmx_chan_formats(ch_, &minspeed, &maxspeed);
    bool has32 = false, has16 = false;
    for (int i = 0; fmts && fmts[i]; i++) {
        if (fmts[i] == NMX_FMT(NMX_AFMT_S32_LE, 2)) has32 = true;
        if (fmts[i] == NMX_FMT(NMX_AFMT_S16_LE, 2)) has16 = true;
    }
    if (!has16 && !has32) {
        IOLog("NMXAudio: %s has no stereo PCM format\n", nmx_pcm_name(sc_));
        return false;
    }
    sampleBits_ = has32 ? 32 : 16;
    frameBytes_ = 2 * (sampleBits_ / 8);
    if (nmx_chan_setformat(ch_, NMX_FMT(has32 ? NMX_AFMT_S32_LE : NMX_AFMT_S16_LE, 2)) != 0)
        return false;
    UInt32 rate = nmx_chan_setspeed(ch_, 48000);
    /* 16 blocks of 512 frames: an interrupt every 10.7 ms at 48 kHz, 170 ms of ring */
    nmx_chan_setfragments(ch_, 512 * frameBytes_, 16);
    UInt32 blksz = 0;
    ring_ = nmx_chan_ring(ch_, &ringBytes_, &blksz);
    if (ring_ == nullptr || ringBytes_ < frameBytes_ * 64)
        return false;
    frames_ = ringBytes_ / frameBytes_;

    setDescription(displayName_ ? displayName_ :
        pcmLabel(sc_, nmx_chan_dir(ch_), pcmLabel_, sizeof(pcmLabel_)));
    IOAudioSampleRate sr = { rate, 0 };
    setSampleRate(&sr);
    setNumSampleFramesPerBuffer(frames_);
    setSampleOffset(blksz / frameBytes_);        /* stay a block ahead of the DMA position */
    setSampleLatency(32);

    stream_ = new IOAudioStream;
    if (stream_ == nullptr || !stream_->initWithAudioEngine(this, output_ ? kIOAudioStreamDirectionOutput :
                                                            kIOAudioStreamDirectionInput, 1))
        return false;
    stream_->setSampleBuffer(ring_, ringBytes_);
    IOAudioStreamFormat fmt = {
        2, kIOAudioStreamSampleFormatLinearPCM, kIOAudioStreamNumericRepresentationSignedInt,
        (UInt8)(sampleBits_ == 32 ? 24 : 16), (UInt8)sampleBits_, kIOAudioStreamAlignmentLowByte,
        kIOAudioStreamByteOrderLittleEndian, true, 0
    };
    IOAudioSampleRate r48 = { 48000, 0 }, r44 = { 44100, 0 };
    stream_->addAvailableFormat(&fmt, &r48, &r48);
    if (minspeed <= 44100 && maxspeed >= 44100)
        stream_->addAvailableFormat(&fmt, &r44, &r44);
    stream_->setFormat(&fmt);
    addAudioStream(stream_);
    stream_->release();

    const UInt32 usage = output_ ? kIOAudioControlUsageOutput : kIOAudioControlUsageInput;
    const auto addLevel = [&](UInt32 channel, const char *name, SInt32 initial) {
        auto *control = IOAudioLevelControl::createVolumeControl(initial, 0, 100, -(64 * 65536), 0,
            channel, name, channel, usage);
        if (control) {
            control->setValueChangeHandler(volumeChanged, this);
            addDefaultAudioControl(control);
            control->release();
        }
    };
    if (displayName_) {
        // CoreAudio derives virtual main volume and balance from the stereo pair.
        addLevel(kIOAudioControlChannelIDDefaultLeft, kIOAudioControlChannelNameLeft, 100);
        addLevel(kIOAudioControlChannelIDDefaultRight, kIOAudioControlChannelNameRight, 100);
        if (nmx_pcm_mixer_devs(sc_) & (1u << NMX_MIXER_VOLUME))
            nmx_pcm_mixer_set(sc_, NMX_MIXER_VOLUME, 100, 100);
    } else {
        addLevel(kIOAudioControlChannelIDAll, kIOAudioControlChannelNameAll, 75);
    }
    IOAudioToggleControl *mute = IOAudioToggleControl::createMuteControl(false, kIOAudioControlChannelIDAll,
        kIOAudioControlChannelNameAll, 0, output_ ? kIOAudioControlUsageOutput : kIOAudioControlUsageInput);
    if (mute) {
        mute->setValueChangeHandler(muteChanged, this);
        addDefaultAudioControl(mute);
        mute->release();
    }
    nmx_chan_set_engine(ch_, this);
    IOLog("NMXAudio: %s %s: %u Hz, %u-bit, ring %u frames\n", nmx_pcm_name(sc_), output_ ? "output" : "input",
          (unsigned)rate, (unsigned)sampleBits_, (unsigned)frames_);
    return true;
}

void NMXAudioEngine::detachChannel()
{
    if (ch_ != nullptr) {
        if (started_)
            nmx_chan_stop(ch_);
        nmx_chan_clear_engine(ch_, this);
        ch_ = nullptr;
        started_ = false;
    }
}

void NMXAudioEngine::stop(IOService *provider)
{
    IOAudioEngine::stop(provider);
    detachChannel();
}

void NMXAudioEngine::free()
{
    detachChannel();
    IOAudioEngine::free();
}

void NMXAudioEngine::setDisplayLevel(UInt32 shift, UInt32 mask, UInt32 level)
{
    UInt32 old = __atomic_load_n(&displayLevels_, __ATOMIC_RELAXED);
    while (!__atomic_compare_exchange_n(&displayLevels_, &old, (old & ~(mask << shift)) | (level << shift),
                                         true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}

IOReturn NMXAudioEngine::volumeChanged(OSObject *target, IOAudioControl *control, SInt32, SInt32 v)
{
    NMXAudioEngine *e = OSDynamicCast(NMXAudioEngine, target);
    if (e == nullptr)
        return kIOReturnBadArgument;
    if (e->displayName_) {
        const UInt32 channel = control->getChannelID();
        if ((channel != kIOAudioControlChannelIDDefaultLeft && channel != kIOAudioControlChannelIDDefaultRight) ||
            v < 0 || v > 100)
            return kIOReturnBadArgument;
        e->setDisplayLevel(channel == kIOAudioControlChannelIDDefaultLeft ? 0 : 8,
                           0xff, static_cast<UInt32>(v));
        return kIOReturnSuccess;
    }
    e->volume_ = v;
    unsigned lvl = e->muted_ ? 0 : (unsigned)v;
    nmx_pcm_mixer_set(e->sc_, e->output_ ? NMX_MIXER_VOLUME : NMX_MIXER_RECLEV, lvl, lvl);
    return kIOReturnSuccess;
}

IOReturn NMXAudioEngine::muteChanged(OSObject *target, IOAudioControl *, SInt32, SInt32 v)
{
    NMXAudioEngine *e = OSDynamicCast(NMXAudioEngine, target);
    if (e == nullptr)
        return kIOReturnBadArgument;
    if (e->displayName_) {
        e->setDisplayLevel(16, 1, v != 0);
        return kIOReturnSuccess;
    }
    e->muted_ = v != 0;
    unsigned lvl = e->muted_ ? 0 : (unsigned)e->volume_;
    nmx_pcm_mixer_set(e->sc_, e->output_ ? NMX_MIXER_VOLUME : NMX_MIXER_RECLEV, lvl, lvl);
    return kIOReturnSuccess;
}

UInt32 NMXAudioEngine::getCurrentSampleFrame()
{
    return (nmx_chan_getptr(ch_) % ringBytes_) / frameBytes_;
}

IOReturn NMXAudioEngine::performAudioEngineStart()
{
    bzero(ring_, ringBytes_);
    lastPtr_ = 0;
    takeTimeStamp(false);
    if (nmx_chan_start(ch_) != 0)
        return kIOReturnError;
    started_ = true;
    return kIOReturnSuccess;
}

IOReturn NMXAudioEngine::performAudioEngineStop()
{
    started_ = false;
    nmx_chan_stop(ch_);
    return kIOReturnSuccess;
}

IOReturn NMXAudioEngine::performFormatChange(IOAudioStream *, const IOAudioStreamFormat *, const IOAudioSampleRate *sr)
{
    if (sr != nullptr) {
        UInt32 got = nmx_chan_setspeed(ch_, sr->whole);
        if (got != sr->whole)
            return kIOReturnUnsupported;
    }
    return kIOReturnSuccess;
}

/* a DMA block finished: the ring wrapped when the position moved backwards, which is when CoreAudio wants a time stamp */
void NMXAudioEngine::blockDone()
{
    if (!started_)
        return;
    UInt32 ptr = nmx_chan_getptr(ch_) % ringBytes_;
    if (ptr < lastPtr_)
        takeTimeStamp();
    lastPtr_ = ptr;
}

IOReturn NMXAudioEngine::clipOutputSamples(const void *mixBuf, void *sampleBuf, UInt32 first, UInt32 n,
                                           const IOAudioStreamFormat *, IOAudioStream *)
{
    if (displayName_) {
        using namespace nmx_display_gain;
        const UInt32 levels = __atomic_load_n(&displayLevels_, __ATOMIC_RELAXED);
        const auto gains = precompute({levels & 0xff, (levels >> 8) & 0xff, (levels & 0x10000) != 0});
        const auto *mix = static_cast<const float *>(mixBuf);
        const bool written = sampleBits_ == 32
            ? writeStereo(mix, frames_, static_cast<SInt32 *>(sampleBuf), frames_, first, n, gains)
            : writeStereo(mix, frames_, static_cast<SInt16 *>(sampleBuf), frames_, first, n, gains);
        return written ? kIOReturnSuccess : kIOReturnBadArgument;
    }
    const float *in = (const float *)mixBuf + first * 2;
    UInt32 count = n * 2;
    if (sampleBits_ == 32) {
        SInt32 *out = (SInt32 *)sampleBuf + first * 2;
        for (UInt32 i = 0; i < count; i++) {
            float s = in[i];
            s = s > 1.0f ? 1.0f : (s < -1.0f ? -1.0f : s);
            out[i] = s >= 1.0f ? 0x7fffffff : (SInt32)(s * 2147483648.0f);
        }
    } else {
        SInt16 *out = (SInt16 *)sampleBuf + first * 2;
        for (UInt32 i = 0; i < count; i++) {
            float s = in[i];
            s = s > 1.0f ? 1.0f : (s < -1.0f ? -1.0f : s);
            out[i] = s >= 1.0f ? 0x7fff : (SInt16)(s * 32768.0f);
        }
    }
    return kIOReturnSuccess;
}


IOReturn NMXAudioEngine::convertInputSamples(const void *sampleBuf, void *destBuf, UInt32 first, UInt32 n,
                                             const IOAudioStreamFormat *, IOAudioStream *)
{
    float *out = (float *)destBuf;
    UInt32 count = n * 2;
    if (sampleBits_ == 32) {
        const SInt32 *in = (const SInt32 *)sampleBuf + first * 2;
        for (UInt32 i = 0; i < count; i++)
            out[i] = (float)in[i] / 2147483648.0f;
    } else {
        const SInt16 *in = (const SInt16 *)sampleBuf + first * 2;
        for (UInt32 i = 0; i < count; i++)
            out[i] = (float)in[i] / 32768.0f;
    }
    return kIOReturnSuccess;
}

/* ---- the device: one per PCM device (an analog codec output, an HDMI/DP port) */

class NMXAudioDevice : public IOAudioDevice {
    OSDeclareDefaultStructors(NMXAudioDevice)
    struct snddev_info *sc_;
    struct nmx_display_endpoint display_ {};
    bool hasDisplay_ = false;
    char pcmLabel_[192] = {};
public:
    struct snddev_info *softc() const { return sc_; }
    bool hasDisplay() const { return hasDisplay_; }
    bool initFor(struct snddev_info *sc, const struct nmx_display_endpoint *display)
    {
        sc_ = sc;
        if (display) {
            display_ = *display;
            hasDisplay_ = true;
        }
        return IOAudioDevice::init(nullptr);
    }
    bool initHardware(IOService *provider) override;
};
OSDefineMetaClassAndStructors(NMXAudioDevice, IOAudioDevice)

bool NMXAudioDevice::initHardware(IOService *provider)
{
    if (!IOAudioDevice::initHardware(provider))
        return false;
    int labelDirection = nmx_chan_dir(nmx_pcm_chan(sc_, 0));
    const char *name = hasDisplay_ ? (display_.name[0] ? display_.name : audioText(NMX_AUDIO_TEXT_DISPLAY_AUDIO))
                                   : pcmLabel(sc_, labelDirection,
                                       pcmLabel_, sizeof(pcmLabel_));
    setDeviceName(name);
    setDeviceShortName(name);
    if (!hasDisplay_) {
        struct nmx_pcm_label_metadata metadata = {};
        if (nmx_pcm_get_label_metadata(sc_, labelDirection, &metadata))
            publishPinMetadata(this, &metadata);
    }
    setManufacturerName("NullMoth");
    if (hasDisplay_)
        setDeviceTransportType(display_.connector == 1 ? kIOAudioDeviceTransportTypeDisplayPort : kIOAudioDeviceTransportTypeHdmi);
    int engines = 0;
    for (int i = 0; i < nmx_pcm_nchan(sc_); i++) {
        NMXAudioEngine *e = new NMXAudioEngine;
        if (e && e->initFor(sc_, nmx_pcm_chan(sc_, i), hasDisplay_ ? name : nullptr) &&
            activateAudioEngine(e) == kIOReturnSuccess)
            engines++;
        if (e)
            e->release();
    }
    return engines > 0;
}

/* ---- the PCI driver */

class NMXAudio : public IOService {
    OSDeclareDefaultStructors(NMXAudio)
    IOPCIDevice *pci_;
    void *dev_;
    volatile int attach_;
    struct DisplayPCM {
        struct snddev_info *pcm = nullptr;
        struct nmx_display_endpoint sink {};
        bool published = false;
        unsigned missed = 0;
    };
    DisplayPCM displays_[16];
    IOWorkLoop *displayLoop_ = nullptr;
    IOTimerEventSource *displayTimer_ = nullptr;
    bool displayPowered_ = false;
    bool displayStopping_ = false;
    static void attachThread(void *arg, wait_result_t);
    static void displayPoll(OSObject *target, IOTimerEventSource *timer);
    void startDisplayPoll();
public:
    IOService *probe(IOService *provider, SInt32 *score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn setPowerState(unsigned long state, IOService *device) override;
    void systemWillShutdown(IOOptionBits spec) override;
    void trackDisplay(struct snddev_info *sc);
    void forgetDisplay(struct snddev_info *sc);
};
OSDefineMetaClassAndStructors(NMXAudio, IOService)

// Serializes attach, periodic CoreAudio publication and PCM removal. The
// FreeBSD attach/detach calls can themselves register and unregister PCMs.
static IORecursiveLock *g_lock;
static bool g_started;
static NMXAudio *g_attaching;          /* the controller whose drivers are attaching (attaches run one at a time) */
static OSArray *g_devices;             /* the NMXAudioDevice objects published */
static OSArray *g_controllers;

static void loadLocale();

static bool enabled()
{
    int v = 0;
    if (PE_parse_boot_argn("-nvoff", &v, sizeof(v)))
        return false;
    if (PE_parse_boot_argn("nmxaudio", &v, sizeof(v)))
        return v != 0;
    return version_major >= 25;        /* Darwin 25 = macOS 26, the first macOS without AppleHDA */
}

IOService *NMXAudio::probe(IOService *provider, SInt32 *score)
{
    auto *pci = OSDynamicCast(IOPCIDevice, provider);
    if (pci == nullptr || !enabled())
        return nullptr;

    // Apple's HDA controller gets first refusal on onboard audio. Preserve
    // the configured priority for NVIDIA display audio.
    constexpr UInt16 nvidiaVendor = 0x10de;
    constexpr SInt32 fallbackScore = -1000;
    if (score != nullptr && pci->configRead16(kIOPCIConfigVendorID) != nvidiaVendor)
        *score = fallbackScore;

    return IOService::probe(provider, score);
}

static int register_drivers()
{
    struct nmx_drvmod *mods[] = { &nmx_drvmod_snd_hda_pci, &nmx_drvmod_snd_hda_hdac, &nmx_drvmod_snd_hda_hdacc,
                                  &nmx_drvmod_snd_hda_pcm_hdaa };
    for (struct nmx_drvmod *m : mods) {
        int err = devclass_add_driver(devclass_create(m->bus), m->driver, 0, nullptr);
        if (err)
            return err;
    }
    return 0;
}

bool NMXAudio::start(IOService *provider)
{
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, provider);
    if (pci == nullptr || g_lock == nullptr || !IOService::start(provider))
        return false;
    IORecursiveLockLock(g_lock);
    if (!g_started) {
        int err = nmx_port_start();
        if (err == 0) {
            err = register_drivers();
            if (err)
                nmx_port_stop();
        }
        if (err) {
            IORecursiveLockUnlock(g_lock);
            IOLog("NMXAudio: the driver layer did not start (%d)\n", err);
            IOService::stop(provider);
            return false;
        }
        loadLocale();
        g_started = true;
    }
    IORecursiveLockUnlock(g_lock);
    pci->setMemoryEnable(true);
    pci->setBusMasterEnable(true);
    pci_ = pci;
    dev_ = nullptr;
    attach_ = 0;
    /* codec probing sends hundreds of verbs; it runs on its own thread so boot matching does not wait for it */
    retain();
    thread_t t = THREAD_NULL;
    if (kernel_thread_start(&NMXAudio::attachThread, this, &t) != KERN_SUCCESS) {
        attach_ = -1;
        release();
        return true;
    }
    thread_deallocate(t);
    return true;
}

/*
 * Boot guard, as NMXNPU's. A driver that panics while it attaches at boot would panic again on every boot. Before the
 * first attach of a boot the kext sets an NVRAM marker and writes it out; it clears it two minutes after the devices are
 * up (attach, engines, first interrupts). A boot that finds the marker set follows one that did not get there - a panic
 * or a hang - so NMXAudio stays off for that boot and says so; the boot after that tries again.
 */
static const char *const kAttachMarker = "nullmoth-audio-attaching";

static IODTNVRAM *nmx_nvram()
{
    IORegistryEntry *e = IORegistryEntry::fromPath("/options", gIODTPlane);
    IODTNVRAM *n = OSDynamicCast(IODTNVRAM, e);
    if (n == nullptr && e != nullptr)
        e->release();
    return n;
}

static void loadLocale()
{
    char value[64] = {};
    if (PE_parse_boot_argn("nmxaudiolang", value, sizeof(value))) {
        value[sizeof(value) - 1] = 0;
        g_locale = nmxAudioLocale(value);
        return;
    }
    auto *nvram = nmx_nvram();
    if (!nvram)
        return;
    OSObject *property = nvram->copyProperty("prev-lang:kbd");
    if (auto *string = OSDynamicCast(OSString, property)) {
        g_locale = nmxAudioLocale(string->getCStringNoCopy());
    } else if (auto *data = OSDynamicCast(OSData, property)) {
        if (data->getLength() < sizeof(value)) {
            memcpy(value, data->getBytesNoCopy(), data->getLength());
            g_locale = nmxAudioLocale(value);
        }
    }
    if (property)
        property->release();
    nvram->release();
}

static bool nmx_marker_set()
{
    IODTNVRAM *n = nmx_nvram();
    if (n == nullptr)
        return false;
    OSObject *v = n->copyProperty(kAttachMarker);
    bool set = v != nullptr;
    if (v)
        v->release();
    n->release();
    return set;
}

static void nmx_marker_write(bool on)
{
    IODTNVRAM *n = nmx_nvram();
    if (n == nullptr) {
        IOLog("NMXAudio: no NVRAM; the boot guard is off\n");
        return;
    }
    const OSSymbol *k = OSSymbol::withCString(kAttachMarker);
    if (k != nullptr) {
        if (on) {
            OSData *d = OSData::withBytes("1", 1);
            if (d == nullptr || !n->setProperty(k, d))
                IOLog("NMXAudio: could not set the boot guard\n");
            if (d)
                d->release();
        } else {
            n->removeProperty(k);
        }
        k->release();
    }
    n->sync();
    n->release();
}

static int g_guard;     /* 0 = not checked this boot, 1 = armed by this boot, -1 = the last boot never cleared it */

void NMXAudio::attachThread(void *arg, wait_result_t)
{
    NMXAudio *self = (NMXAudio *)arg;
    IORecursiveLockLock(g_lock);
    if (self->displayStopping_) {
        IORecursiveLockUnlock(g_lock);
        self->attach_ = -1;
        self->release();
        return;
    }
    if (g_guard == 0) {
        if (nmx_marker_set()) {
            g_guard = -1;
            nmx_marker_write(false);     /* the next boot tries again */
        } else {
            g_guard = 1;
            nmx_marker_write(true);
        }
    }
    if (g_guard < 0) {
        IORecursiveLockUnlock(g_lock);
        IOLog("NMXAudio: the last boot stopped while audio was starting; audio stays off this boot\n");
        self->setProperty("nullmoth-audio-state", "parked: the last boot stopped while audio was starting");
        self->attach_ = -1;
        self->release();
        return;
    }
    g_controllers->setObject(self);
    g_attaching = self;
    self->dev_ = nmx_port_attach_pci(self->pci_);
    g_attaching = nullptr;
    self->displayPowered_ = self->dev_ != nullptr;
    IORecursiveLockUnlock(g_lock);
    if (self->dev_ == nullptr) {
        IOLog("NMXAudio: no driver took %04x:%04x\n", self->pci_->configRead16(kIOPCIConfigVendorID),
              self->pci_->configRead16(kIOPCIConfigDeviceID));
        self->attach_ = -1;
    } else {
        static IOPMPowerState states[2] = {
            { kIOPMPowerStateVersion1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { kIOPMPowerStateVersion1, kIOPMPowerOn, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        self->PMinit();
        self->pci_->joinPMtree(self);
        self->registerPowerDriver(self, states, 2);
        self->registerService();
        self->startDisplayPoll();
        self->attach_ = 1;
    }
    /* the guard comes off once audio has run for two minutes (the first controller's thread does it) */
    static volatile SInt32 clearing;
    if (g_guard > 0 && OSCompareAndSwap(0, 1, &clearing)) {
        IOSleep(120 * 1000);
        nmx_marker_write(false);
        IOLog("NMXAudio: up for two minutes; boot guard cleared\n");
    }
    self->release();
}

static bool publishDevice(NMXAudio *owner, struct snddev_info *sc, const nmx_display_endpoint *sink)
{
    NMXAudioDevice *d = new NMXAudioDevice;
    if (d == nullptr)
        return false;
    const bool attached = d->initFor(sc, sink) && d->attach(owner);
    const bool started = attached && d->start(owner);
    if (started) {
        g_devices->setObject(d);
    } else {
        IOLog("NMXAudio: %s could not be published\n", nmx_pcm_name(sc));
        if (attached)
            d->detach(owner);
    }
    d->release();
    return started;
}

// Use IOKit termination for display detach so CoreAudio drops the HAL entry.
static bool unpublishDevice(struct snddev_info *sc)
{
    for (unsigned i = 0; i < g_devices->getCount(); i++) {
        auto *d = OSDynamicCast(NMXAudioDevice, g_devices->getObject(i));
        if (!d || d->softc() != sc)
            continue;
        if (d->hasDisplay()) {
            if (!d->terminate(kIOServiceRequired | kIOServiceSynchronous))
                return false;
        } else {
            IOService *owner = d->getProvider();
            d->stop(owner);
            d->detach(owner);
        }
        g_devices->removeObject(i);
        break;
    }
    return true;
}

void NMXAudio::trackDisplay(struct snddev_info *sc)
{
    for (auto &display : displays_) {
        if (display.pcm == nullptr) {
            display.pcm = sc;
            return;
        }
    }
    IOLog("NMXAudio: display PCM limit reached\n");
}

void NMXAudio::forgetDisplay(struct snddev_info *sc)
{
    for (auto &display : displays_) {
        if (display.pcm == sc) {
            display = {};
            return;
        }
    }
}

void NMXAudio::startDisplayPoll()
{
    bool tracked = false;
    for (const auto &display : displays_)
        tracked |= display.pcm != nullptr;
    if (!tracked)
        return;
    displayLoop_ = IOWorkLoop::workLoop();
    if (!displayLoop_)
        return;
    displayTimer_ = IOTimerEventSource::timerEventSource(this, displayPoll);
    if (!displayTimer_ || displayLoop_->addEventSource(displayTimer_) != kIOReturnSuccess) {
        if (displayTimer_)
            displayTimer_->release();
        displayTimer_ = nullptr;
        displayLoop_->release();
        displayLoop_ = nullptr;
        return;
    }
    displayTimer_->setTimeoutMS(350);
}

void NMXAudio::displayPoll(OSObject *target, IOTimerEventSource *timer)
{
    auto *owner = static_cast<NMXAudio *>(target);
    IORecursiveLockLock(g_lock);
    if (owner->displayPowered_ && !owner->displayStopping_) {
        for (auto &display : owner->displays_) {
            if (!display.pcm)
                continue;
            nmx_display_endpoint sink {};
            const bool present = nmx_pcm_display_endpoint(display.pcm, &sink) == NMX_DISPLAY_CONNECTED;
            display.missed = present ? 0 : display.missed + (display.missed < 2);
            const bool changed = present &&
                (sink.connector != display.sink.connector || sink.manufacturer != display.sink.manufacturer ||
                 sink.product != display.sink.product || strcmp(sink.name, display.sink.name) != 0);
            if (display.published && (changed || display.missed == 2) && unpublishDevice(display.pcm))
                display.published = false;
            if (present && !display.published && publishDevice(owner, display.pcm, &sink)) {
                display.sink = sink;
                display.published = true;
            }
        }
    }
    if (!owner->displayStopping_)
        timer->setTimeoutMS(1000);
    IORecursiveLockUnlock(g_lock);
}

/* pcm_register runs on the attaching controller, before its poller starts. */
extern "C" void nmx_audio_publish(struct snddev_info *sc)
{
    NMXAudio *owner = g_attaching;
    if (!owner || nmx_pcm_nchan(sc) == 0)
        return;
    if (nmx_pcm_display_endpoint(sc, nullptr) == NMX_DISPLAY_LOCAL)
        publishDevice(owner, sc, nullptr);
    else
        owner->trackDisplay(sc);
}

extern "C" void nmx_audio_diag_publish(const char *text)
{
    if (g_attaching != nullptr && text != nullptr)
        g_attaching->setProperty("nmx-hda-diag", text);
}

extern "C" int nmx_audio_unpublish(struct snddev_info *sc)
{
    IORecursiveLockLock(g_lock);
    const bool removed = unpublishDevice(sc);
    if (removed) {
        for (unsigned i = 0; i < g_controllers->getCount(); ++i) {
            auto *owner = OSDynamicCast(NMXAudio, g_controllers->getObject(i));
            if (owner)
                owner->forgetDisplay(sc);
        }
    }
    IORecursiveLockUnlock(g_lock);
    return removed ? 0 : EBUSY;
}

extern "C" void nmx_audio_block_done(void *engine, struct pcm_channel *)
{
    ((NMXAudioEngine *)engine)->blockDone();
}

void NMXAudio::stop(IOService *provider)
{
    IORecursiveLockLock(g_lock);
    displayStopping_ = true;
    IORecursiveLockUnlock(g_lock);
    for (int i = 0; attach_ == 0 && i < 600; i++)
        IOSleep(100);
    if (attach_ == 1)
        PMstop();
    if (displayTimer_) {
        displayTimer_->cancelTimeout();
        displayLoop_->removeEventSource(displayTimer_);
        displayTimer_->release();
        displayLoop_->release();
        displayTimer_ = nullptr;
        displayLoop_ = nullptr;
    }
    IORecursiveLockLock(g_lock);
    nmx_port_detach(dev_);
    dev_ = nullptr;
    const unsigned index = g_controllers->getNextIndexOfObject(this, 0);
    if (index < g_controllers->getCount())
        g_controllers->removeObject(index);
    IORecursiveLockUnlock(g_lock);
    IOService::stop(provider);
}

IOReturn NMXAudio::setPowerState(unsigned long state, IOService *)
{
    IORecursiveLockLock(g_lock);
    displayPowered_ = false;
    if (dev_ != nullptr) {
        int err = nmx_port_power(dev_, state != 0);
        displayPowered_ = state != 0 && err == 0;
        if (err)
            IOLog("NMXAudio: %s returned %d\n", state ? "resume" : "suspend", err);
    }
    IORecursiveLockUnlock(g_lock);
    return kIOPMAckImplied;
}

void NMXAudio::systemWillShutdown(IOOptionBits spec)
{
    IORecursiveLockLock(g_lock);
    displayStopping_ = true;
    if (dev_)
        nmx_port_shutdown(dev_);
    IORecursiveLockUnlock(g_lock);
    IOService::systemWillShutdown(spec);
}

extern "C" {
kern_return_t nmx_audio_kmod_start(kmod_info_t *ki, void *data);
kern_return_t nmx_audio_kmod_stop(kmod_info_t *ki, void *data);
}

kern_return_t nmx_audio_kmod_start(kmod_info_t *, void *)
{
    g_lock = IORecursiveLockAlloc();
    g_devices = OSArray::withCapacity(8);
    g_controllers = OSArray::withCapacity(4);
    return g_lock && g_devices && g_controllers ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t nmx_audio_kmod_stop(kmod_info_t *, void *)
{
    if (g_started)
        nmx_port_stop();
    if (g_devices)
        g_devices->release();
    if (g_controllers)
        g_controllers->release();
    if (g_lock)
        IORecursiveLockFree(g_lock);
    return KERN_SUCCESS;
}

extern "C" {
kern_return_t _start(kmod_info_t *ki, void *data);
kern_return_t _stop(kmod_info_t *ki, void *data);
KMOD_EXPLICIT_DECL(com.nullmoth.NMXAudio, "1.0.2", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = nmx_audio_kmod_start;
__private_extern__ kmod_stop_func_t *_antimain = nmx_audio_kmod_stop;
}
