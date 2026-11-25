#ifndef NMX_DISPLAY_GAIN_H
#define NMX_DISPLAY_GAIN_H

#include <stddef.h>
#include <stdint.h>

namespace nmx_display_gain {

// A value snapshot suitable for passing into the sample callback. Callers own
// synchronization when updating these controls on a live audio engine.
struct Levels {
    unsigned left = 100;
    unsigned right = 100;
    bool muted = false;
};

struct ChannelGains {
    float left = 1.0f;
    float right = 1.0f;
};

inline float levelGain(unsigned level) noexcept
{
    if (level >= 100)
        return 1.0f; // Keep unity exact; do not run it through a curve.
    // IOAudioFamily exposes the square of the normalized integer step as
    // the HAL volume scalar. Use that same scalar for PCM amplitude.
    const float step = static_cast<float>(level) / 100.0f;
    return step * step;
}

inline ChannelGains precompute(const Levels &levels) noexcept
{
    if (levels.muted)
        return {0.0f, 0.0f};
    return {levelGain(levels.left), levelGain(levels.right)};
}

inline float boundedGain(float gain) noexcept
{
    if (!(gain == gain)) // NaN
        return 0.0f;
    if (gain <= 0.0f)
        return 0.0f;
    if (gain >= 1.0f)
        return 1.0f;
    return gain;
}

template <typename Sample>
struct PcmTraits {
    static_assert(sizeof(Sample) == 0, "only signed 16-bit and 32-bit PCM are supported");
};

template <>
struct PcmTraits<int16_t> {
    static int16_t fromFloat(float scaled) noexcept
    {
        return scaled >= 1.0f ? static_cast<int16_t>(0x7fff)
                              : static_cast<int16_t>(scaled * 32768.0f);
    }
};

template <>
struct PcmTraits<int32_t> {
    static int32_t fromFloat(float scaled) noexcept
    {
        return scaled >= 1.0f ? static_cast<int32_t>(0x7fffffff)
                              : static_cast<int32_t>(scaled * 2147483648.0f);
    }
};

template <typename Sample>
inline Sample quantize(float input, float gain) noexcept
{
    // A NaN-to-integer cast is undefined. Treat NaN as silence, then apply
    // gain before clipping so an over-range source can still be attenuated.
    if (!(input == input))
        input = 0.0f;
    float scaled = input * boundedGain(gain);
    if (!(scaled == scaled))
        scaled = 0.0f;
    if (scaled > 1.0f)
        scaled = 1.0f;
    else if (scaled < -1.0f)
        scaled = -1.0f;
    return PcmTraits<Sample>::fromFloat(scaled);
}

// Convert interleaved float stereo into a bounded portion of an int16/int32
// ring. `firstFrame` and `numFrames` address both buffers; no wraparound is
// performed. The caller must pass a complete source-frame count for validation.
template <typename Sample>
inline bool writeStereo(const float *mix,
                        size_t mixFrames,
                        Sample *ring,
                        size_t ringFrames,
                        size_t firstFrame,
                        size_t numFrames,
                        const ChannelGains &gains) noexcept
{
    const size_t maxFrames = static_cast<size_t>(-1) / 2;
    if (mixFrames > maxFrames || ringFrames > maxFrames ||
        firstFrame > mixFrames || numFrames > mixFrames - firstFrame ||
        firstFrame > ringFrames || numFrames > ringFrames - firstFrame ||
        (numFrames != 0 && (mix == nullptr || ring == nullptr)))
        return false;

    const size_t endFrame = firstFrame + numFrames;
    const float leftGain = boundedGain(gains.left);
    const float rightGain = boundedGain(gains.right);
    for (size_t frame = firstFrame; frame < endFrame; ++frame) {
        const size_t sample = frame * 2;
        ring[sample] = quantize<Sample>(mix[sample], leftGain);
        ring[sample + 1] = quantize<Sample>(mix[sample + 1], rightGain);
    }
    return true;
}

} // namespace nmx_display_gain

#endif // NMX_DISPLAY_GAIN_H
