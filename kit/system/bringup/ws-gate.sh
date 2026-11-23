#!/bin/bash
# Starts the window server once the NVIDIA display is ready. It is the window server's launch entry.
WS=/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer
MARK=/var/run/ws-gate.done          # /var/run is emptied at every boot
LOG=/var/log/nullmoth-ws-gate.log
WAIT_TRIES=150                      # x 2 s = 300 s
COREDISPLAY=/Library/Preferences/com.apple.CoreDisplay
say() { echo "$(date '+%F %T') $*" >> "$LOG"; }

sysctl_r()    { /usr/sbin/sysctl -n "$1" 2>/dev/null; }
sysctl_w()    { /usr/sbin/sysctl -w "$1=$2" >> "$LOG" 2>&1; }
IOREG=/usr/sbin/ioreg
ACCEL_CLASS=NVAccel
FB_CLASS=NVRMNVDAFramebuffer        # what ioreg is asked for (a subclass answers too)
FB_CLASS_RE=NVRMNVDAFramebuffer     # the class names a listing may show for it
IOP_KEY=useIOP_onNVIDIA
accel_props() { "$IOREG" -r -c "$ACCEL_CLASS" -d 1 -l 2>/dev/null; }
accel_pipe()  { "$IOREG" -r -c "$ACCEL_CLASS" -d 1 -l 2>/dev/null; }
fb_props()    { "$IOREG" -r -c "$FB_CLASS" -d 1 -l 2>/dev/null; }
coredisplay_set() { /usr/bin/defaults write "$COREDISPLAY" "$IOP_KEY" -bool true; }
coredisplay_off() { /usr/bin/defaults write "$COREDISPLAY" "$IOP_KEY" -bool false; }
coredisplay_get() { /usr/bin/defaults read "$COREDISPLAY" "$IOP_KEY" 2>/dev/null; }
start_windowserver() { exec "$WS" "$@"; }
# A laptop whose built-in screen is wired to its own graphics chip: the NVIDIA card lists its connectors and none has
# a display (NVRMFB publishes connected-displays on each nub it enumerated, about 7 s after start), and another
# graphics chip (PCI class 03, vendor not NVIDIA) is present, so the firmware's picture on that chip is the screen.
# Waiting for an NVIDIA head there only meant minutes of black screen and restarts that could never help.
# Prints "yes <other chips>" or "no <why>"; DISPLAY_ELSEWHERE_IOREG lets a test feed it a registry listing.
display_elsewhere() {
  local cds other
  if [ -n "${DISPLAY_ELSEWHERE_IOREG:-}" ]; then cds=$(cat "$DISPLAY_ELSEWHERE_IOREG")
  else cds=$(/usr/sbin/ioreg -lw0 2>/dev/null); fi
  other=$(printf '%s\n' "$cds" | LC_ALL=C awk '
    function flush() { if (disp && ven != "" && ven != "de10") n++; disp = 0; ven = "" }
    /\+-o / { flush() }
    /"class-code" = <....03..>/ { disp = 1 }
    /"vendor-id" = </ { i = index($0, "<"); ven = substr($0, i + 1, 4) }
    END { flush(); print n + 0 }')
  cds=$(printf '%s\n' "$cds" | LC_ALL=C sed -n 's/.*"connected-displays" = \([0-9][0-9]*\).*/\1/p')
  if [ -z "$cds" ]; then echo "no (the NVIDIA card has not listed its connectors yet)"; return 1; fi
  if printf '%s\n' "$cds" | grep -qv '^0$'; then echo "no (a display is connected to the NVIDIA card)"; return 1; fi
  if [ "$other" -lt 1 ]; then echo "no (no other graphics chip: the screen can only be on the NVIDIA card)"; return 1; fi
  echo "yes ($other other graphics chip(s))"; return 0
}
ELSEWHERE_MARK=/var/run/nullmoth-display-elsewhere   # emptied at every boot
GFXPATH=/Library/NullMoth/bringup/graphics-path
graphics_path() { cat "$GFXPATH" 2>/dev/null; }
apple_accel()   { "$IOREG" -r -c IOAccelerator -d 1 2>/dev/null; }
nmx_fb()        { "$IOREG" -r -c NMXGPUFB -d 1 2>/dev/null; }
nmx_gpu()       { "$IOREG" -r -c NMXGPU -d 1 -l 2>/dev/null; }
await_nmx_fb() {
  local i st
  say "== first WindowServer start this boot: waiting for the AMD/Intel driver's framebuffer (up to $((WAIT_TRIES * 2)) s)"
  for i in $(seq 1 "$WAIT_TRIES"); do
    if nmx_fb | grep -E -q '<class NMXGPU(Intel|AMD)?FB'; then
      say "framebuffer after ~$((i * 2)) s - starting WindowServer on it"
      echo "nmx $(date '+%T')" >> "$MARK"; return 0
    fi
    st=$(nmx_gpu | grep -o '"nullmoth-gpu-state" = "[^"]*"' | head -1)
    if [ -n "$st" ]; then
      say "the AMD/Intel driver left the GPU to the firmware ($st) - starting WindowServer on the firmware's framebuffer"
      echo "firmware $(date '+%T') nmx-left" >> "$MARK"; return 1
    fi
    sleep 2
  done
  say "timed out: no AMD/Intel framebuffer after $((WAIT_TRIES * 2)) s - starting WindowServer on the firmware's framebuffer"
  echo "firmware $(date '+%T') no-nmx-framebuffer" >> "$MARK"; return 1
}
nmx_vendor() {
  local out
  out=$(nmx_fb)
  case "$out" in *'<class NMXGPUIntelFB'*) echo IG;; *'<class NMXGPUAMDFB'*) echo AMD;; esac
}
nmx_select() {
  local v
  v=$(nmx_vendor)
  [ -n "$v" ] || return 1
  ACCEL_CLASS=NMXAccel; FB_CLASS=NMXGPUFB; FB_CLASS_RE='NMXGPUIntelFB|NMXGPUAMDFB'; IOP_KEY=useIOP_on$v
  return 0
}
nmx_off() {
  coredisplay_off
  say "$1 - $IOP_KEY off, the window server composites in software onto NMXGPU's framebuffer"
  echo "software $(date '+%T') $2" >> "$MARK"
}
arm_nmx_pipe() {
  local i h ok=0 armed caps how
  if ! nmx_select; then
    say "NMXGPU's framebuffer names no vendor (nmxfb_pipe=1 is not set): no display pipe to arm"
    return
  fi
  if [ "$(sysctl_r debug.nmxaccel_pipe)" != 1 ]; then
    nmx_off "NMXAccel is not running with nmxfb_pipe=1 (debug.nmxaccel_pipe: $(sysctl_r debug.nmxaccel_pipe))" nmx-no-accelerator-pipe
    return
  fi
  for i in $(seq 1 "$WAIT_TRIES"); do
    h=$(sysctl_r debug.nmxaccel_heads_published)
    case "$h" in ''|*[!0-9]*) ;; *) if [ $((h & 1)) = 1 ]; then ok=1; break; fi;; esac
    sleep 2
  done
  if [ $ok != 1 ]; then
    nmx_off "timed out: NMXGPU's framebuffer did not become head 0 of NMXAccel in $((WAIT_TRIES * 2)) s" nmx-no-head
    return
  fi
  armed=$(sysctl_r debug.nmxaccelfb)
  case "$armed" in
    '') nmx_off "head 0 after ~$((i * 2)) s; debug.nmxaccelfb does not answer - not arming" nmx-no-control; return;;
    0) sysctl_w debug.nmxaccelfb 1; sleep 1
       if [ "$(sysctl_r debug.nmxaccelfb)" != 1 ]; then nmx_off "level 1 did not take" nmx-level1; return; fi
       sysctl_w debug.nmxaccelfb 4; sleep 2; how="armed 1->4";;
    *) how="already at level $armed";;
  esac
  sysctl_w debug.nmxaccel_iop 1
  coredisplay_set
  caps=$(pipe_caps)
  say "NMXAccel head 0 after ~$((i * 2)) s; $how + IOP, $IOP_KEY on, display-pipe capabilities $caps"
  echo "armed $(date '+%T') nmx caps=$caps" > "$MARK"
}
await_apple_accel() {
  local i
  say "== first WindowServer start this boot: waiting for Apple's graphics accelerator (up to $((WAIT_TRIES * 2)) s)"
  for i in $(seq 1 "$WAIT_TRIES"); do
    if apple_accel | grep -q '<class '; then
      say "accelerator after ~$((i * 2)) s - starting WindowServer on it"
      echo "apple $(date '+%T')" >> "$MARK"; return 0
    fi
    sleep 2
  done
  say "timed out: no accelerator after $((WAIT_TRIES * 2)) s - starting WindowServer without it"
  echo "software $(date '+%T') no-apple-accelerator" >> "$MARK"; return 1
}
CRYPTEX_PLACE=/Library/NullMoth/bringup/cryptex-place.sh
place_cryptexes() { [ -f "$CRYPTEX_PLACE" ] || return 0; /bin/bash "$CRYPTEX_PLACE" >> "$LOG" 2>&1; return 0; }

pipe_caps() {
  local out
  out=$(accel_pipe) || { echo unknown; return; }
  [ -n "$out" ] || { echo unknown; return; }
  printf '%s\n' "$out" | grep -c IOAccelDisplayPipeCapabilities
}

plugin_name_back() {
  local out
  out=$(accel_props) || { echo unknown; return; }
  [ -n "$out" ] || { echo unknown; return; }
  printf '%s\n' "$out" | grep -q '"MetalPluginName" = "' && echo 1 || echo 0
}

fb_link() {
  local out fbs linked id
  out=$(fb_props) || { echo unknown; return; }
  [ -n "$out" ] || { echo "0 0 -"; return; }
  fbs=$(printf '%s\n' "$out" | grep -E -c "<class ($FB_CLASS_RE),")
  linked=$(printf '%s\n' "$out" | grep -c '"IOAccelTypes" = "')
  id=$(printf '%s\n' "$out" | sed -n -E "s/.*<class ($FB_CLASS_RE), id (0x[0-9a-f]*).*/\2/p" | head -n 1)
  echo "$fbs $linked ${id:--}"
}

await_fb_link() {
  local r fbs linked id i=0 accel
  r=$(fb_link)
  while [ "$r" != unknown ] && [ $i -lt 10 ]; do
    set -- $r; fbs=$1; linked=$2
    [ "$fbs" -gt 0 ] && [ "$linked" -ge "$fbs" ] && break
    sleep 2; i=$((i + 1)); r=$(fb_link)
  done
  accel=$(accel_props | sed -n "s/.*<class $ACCEL_CLASS, id \(0x[0-9a-f]*\).*/\1/p" | head -n 1)
  if [ "$r" = unknown ]; then say "framebuffer link: the registry did not answer"; return; fi
  set -- $r; fbs=$1; linked=$2; id=$3
  say "framebuffer link: $linked of $fbs framebuffer(s) name their accelerator (framebuffer $id, accelerator ${accel:--})$([ $i -gt 0 ] && echo ", waited $((i * 2)) s")$([ "$fbs" -gt 0 ] && [ "$linked" -lt "$fbs" ] && echo " - NOT LINKED: the window server is expected to find no display pipe")"
}

record_preconditions() {
  local mpn caps iop missing=""
  mpn=$(plugin_name_back); caps=$(pipe_caps); iop=$(coredisplay_get)
  [ -z "$iop" ] && iop=unset
  case "$mpn" in 1) ;; unknown) missing="$missing accelerator-unreadable";; *) missing="$missing metal-plugin-name-withheld";; esac
  case "$caps" in unknown) [ "$mpn" = unknown ] || missing="$missing accelerator-unreadable";;
                  0) missing="$missing no-display-pipe-capabilities";; esac
  [ "$iop" = 1 ] || missing="$missing coredisplay-useIOP-$iop"
  if [ -n "$missing" ]; then
    say "REFUSING the Metal pipe for this start -$missing (plugin-name $mpn, capabilities $caps, useIOP $iop):"
    say "  starting the window server on the software compositor, which has no destination surface here - a session that"
    say "  composites a full desktop is expected to die. Fix what is named above before reading anything else."
    echo "software $(date '+%T')$missing" >> "$MARK"
    return 1
  else
    say "pre-exec: Metal plugin name back, display-pipe capabilities $caps, useIOP 1 - starting on the Metal pipe"
    echo "ready $(date '+%T') caps=$caps" >> "$MARK"
  fi
}

LINK_TRIES=30                       # x 2 s = 60 s
await_link_controls() {
  local i=0
  while [ $i -lt "$LINK_TRIES" ]; do
    [ -n "$(sysctl_r debug.nvrmfb_agdc_k5)" ] && [ -n "$(sysctl_r debug.nvrmfb_agdc)" ] && break
    sleep 2; i=$((i + 1))
  done
  if [ $i -ge "$LINK_TRIES" ]; then
    say "display link controls: NO ANSWER after $((LINK_TRIES * 2)) s - the link cannot be turned on; the window server is expected to find no display pipe"
    return 1
  fi
  [ $i -gt 0 ] && say "display link controls answered after $((i * 2)) s"
  return 0
}

LINK_ON_TRIES=10                    # x 1 s
link_on() {
  local i=0 k5 ag
  sysctl_w debug.nvrmfb_agdc_k5 1
  sysctl_w debug.nvrmfb_agdc 1
  while [ $i -lt "$LINK_ON_TRIES" ]; do
    k5=$(sysctl_r debug.nvrmfb_agdc_k5); ag=$(sysctl_r debug.nvrmfb_agdc)
    [ "$k5" = 1 ] && [ "$ag" = 1 ] && return 0
    sleep 1; i=$((i + 1))
  done
  say "display link NOT ON $LINK_ON_TRIES s after the arm (K5 ${k5:-unset}, AGDC ${ag:-unset}): the window server is expected to find no display pipe"
  return 1
}

arm_pipe() {
  local i h ok=0
  say "== first WindowServer start this boot: waiting for NVAccel's display head (up to $((WAIT_TRIES * 2)) s)"
  local seen=0 why
  for i in $(seq 1 "$WAIT_TRIES"); do
    h=$(sysctl_r debug.nvaccel_heads_published)
    if [ -n "$h" ] && [ "$h" -ge 1 ]; then ok=1; break; fi
    # three answers in a row (6 s), so a monitor still waking up is not taken for "no display"
    if why=$(display_elsewhere); then seen=$((seen + 1)); else seen=0; fi
    if [ "$seen" -ge 3 ]; then
      say "no display on the NVIDIA card after ~$((i * 2)) s and the screen is on another graphics chip: $why - starting WindowServer on that screen now (the NVIDIA card stays up without a display)"
      coredisplay_off; echo "elsewhere $(date '+%T')" > "$ELSEWHERE_MARK"; echo "elsewhere $(date '+%T')" >> "$MARK"
      return
    fi
    sleep 2
  done
  if [ $ok != 1 ]; then
    say "timed out: no NVAccel head after $((WAIT_TRIES * 2)) s - starting WindowServer on the software compositor"
    return
  fi
  local armed
  armed=$(sysctl_r debug.nvaccelfb)
  if [ -z "$armed" ]; then
    say "head after ~$((i * 2)) s; debug.nvaccelfb does not answer - not arming"
    return
  fi
  if [ "$armed" != 0 ]; then
    local k5 ag
    await_link_controls
    k5=$(sysctl_r debug.nvrmfb_agdc_k5); ag=$(sysctl_r debug.nvrmfb_agdc)
    if [ "$k5" = 1 ] && [ "$ag" = 1 ]; then
      [ -n "$(coredisplay_get)" ] || coredisplay_set
      say "head after ~$((i * 2)) s; nvaccelfb already $armed, K5 and AGDC on - not re-arming (display preference $(coredisplay_get))"
      return
    fi
    link_on
    sysctl_w debug.nvaccel_iop 1
    coredisplay_set
    say "head after ~$((i * 2)) s; nvaccelfb already $armed but K5 was ${k5:-unset} and AGDC ${ag:-unset}: finished the arm (K5/AGDC/IOP), display-pipe capabilities $(pipe_caps)"
    echo "armed $(date '+%T') caps=$(pipe_caps)" > "$MARK"
    return
  fi
  sysctl_w debug.nvaccelfb 1; sleep 1
  if [ "$(sysctl_r debug.nvaccelfb)" != 1 ]; then
    say "level 1 did not take - starting WindowServer on the software compositor"
    return
  fi
  sysctl_w debug.nvaccelfb 4; sleep 2
  await_link_controls
  link_on
  sysctl_w debug.nvaccel_iop 1
  coredisplay_set
  local caps
  caps=$(pipe_caps)
  say "head after ~$((i * 2)) s; armed 1->4 + K5/AGDC/IOP, display-pipe capabilities $caps"
  echo "armed $(date '+%T') caps=$caps" > "$MARK"
}

cap_log() {
  local f=$1 n
  n=$(stat -f %z "$f" 2>/dev/null) || return 0
  [ "$n" -gt 1048576 ] || return 0
  tail -c 524288 "$f" > "$f.cap" 2>/dev/null && cat "$f.cap" > "$f"; rm -f "$f.cap"
}
wsgate_main() {
  # Driver off (-nvoff): there is no NVIDIA display head to wait for. The firmware framebuffer is the display, so the
  # window server starts on it at once instead of after the 300 s wait.
  case " $(sysctl_r kern.bootargs) " in *" -nvoff "*)
    say "driver off (-nvoff): starting WindowServer on the firmware framebuffer now"; coredisplay_off
    [ -e "$MARK" ] || echo "firmware $(date '+%T') nvoff" >> "$MARK"; start_windowserver "$@";;
  esac
  cap_log "$LOG"; cap_log /var/log/nullmoth-ws-stderr.log
  if [ ! -e "$MARK" ]; then
    : > "$MARK"
    place_cryptexes
    case "$(graphics_path)" in apple) await_apple_accel;; test) await_nmx_fb && arm_nmx_pipe;; *) arm_pipe;; esac
  fi
  case "$(graphics_path)" in
    apple) ;;
    test) if nmx_select && [ "$(sysctl_r debug.nmxaccel_pipe)" = 1 ]; then
            await_fb_link
            record_preconditions || nmx_off "the Metal pipe is not ready for this start" nmx-preconditions
          fi;;
    *) if [ -e "$ELSEWHERE_MARK" ]; then say "screen on another graphics chip: no Metal display pipe this start"
       else await_fb_link; record_preconditions; fi;;
  esac
  start_windowserver "$@"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    *) wsgate_main "$@";;
  esac
fi

