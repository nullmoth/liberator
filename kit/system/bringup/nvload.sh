#!/bin/bash
# Brings the NVIDIA display up at start-up and puts the window server on it. Run once per start by its launch job.

LOG=/var/log/nullmoth-nvload.log
NVGO=/Library/NullMoth/bringup/nvgo                 # NVRM user client, method 0 = run bring-up pass <n> (root only)
GUARD=7C436110-AB2A-4BBB-A880-FE41995C9F82:nullmoth-nv-starts
HEAD_WAIT_TRIES=300                                 # x 2 s = 600 s for a head
GO2_SETTLE_TRIES=30                                 # x 2 s = 60 s for the retried pass to publish a head
NVGO_SECS=30                                        # nvgo itself is bounded: a pass that never returns must not hold the boot
GO2_RETRIED=0
IDLE_WATCH_TRIES=60                                 # x 3 s = 3 more minutes for an idle desktop's first frame
HEAD_DIAG_TRY=45                                    # x 2 s = 90 s without a head: write down what the driver says, once
HEAD_RESTART_TRY=75                                 # x 2 s = 150 s without a head: one automatic restart (see head_restart)
WSGATE_DONE=/var/run/ws-gate.done                   # written by ws-gate.sh ("armed ...") when it armed the pipe first
PIPE_DONE=/var/run/nvload.pipe                      # "final <time> <outcome>": nvload changes nothing more this boot

say() { echo "$(date '+%F %T') $*"; }

run_bounded() {
  local secs=$1 p w rc; shift
  "$@" & p=$!
  ( /bin/sleep "$secs"; kill -9 "$p" 2>/dev/null ) & w=$!
  wait "$p"; rc=$?
  kill "$w" 2>/dev/null; wait "$w" 2>/dev/null
  [ "$rc" = 137 ] && rc=124
  return $rc
}

heads() { local h; h=$(sysctl -n debug.nvaccel_heads_published 2>/dev/null); case "$h" in ''|*[!0-9]*) echo 0;; *) echo "$h";; esac; }
autogo_state() { ioreg -c NVRM -lw0 2>/dev/null | sed -n 's/.*"nvrm-autogo" = "\([^"]*\)".*/\1/p' | head -n 1; }

go2_retry() {
  local st out rc i h
  [ "$GO2_RETRIED" = 1 ] && return 1
  st=$(autogo_state)
  [ "$st" = "go(2) failed" ] || return 1
  GO2_RETRIED=1
  say "auto-go reports go(2) failed: clearing the start guard, then running go(2) once more"
  nvram -d "$GUARD" 2>/dev/null
  if out=$(nvram "$GUARD" 2>/dev/null) && [ -n "$out" ]; then
    say "go(2) NOT retried: the start guard is still set ($out) - a retry would count as another start"
    return 1
  fi
  say "start guard cleared"
  if [ ! -x "$NVGO" ]; then say "go(2) NOT retried: $NVGO is missing"; return 1; fi
  out=$(run_bounded "$NVGO_SECS" "$NVGO" 2 2>&1); rc=$?
  if [ "$rc" = 124 ]; then say "nvgo 2 did not return within $NVGO_SECS s and was stopped"
  else say "nvgo 2 -> exit $rc: $(printf '%s' "$out" | tr '\n' ' ')"; fi
  h=0
  for i in $(seq 1 "$GO2_SETTLE_TRIES"); do
    h=$(heads); [ "$h" -ge 1 ] && break
    sleep 2
  done
  st=$(autogo_state)
  if [ "$h" -ge 1 ]; then say "go(2) retry RECOVERED: auto-go '$st', $h head(s) published"
  else say "go(2) retry did NOT recover: auto-go '$st', no head after $((GO2_SETTLE_TRIES * 2)) s - the screen stays on the software compositor; a restart usually clears it"; fi
  return 0
}

# What the driver itself says while no head is there. A start that ends on a black screen used to leave only "no head":
# these lines ride in the start report, so the reason is in the first upload.
driver_lines() {   # the kernel driver's own lines of this start, newest last, bounded
  run_bounded 25 /usr/bin/log show --last "${1:-4m}" --style compact \
    --predicate 'process == "kernel" AND (eventMessage CONTAINS "NVRM-xnu" OR eventMessage CONTAINS "NVAccel" OR eventMessage CONTAINS "NVRMFB")' 2>/dev/null \
    | grep -E 'NVRM-xnu|NVAccel|NVRMFB' | sed -E 's/^[0-9-]+ [0-9:.]+ +[A-Za-z]+ +kernel[^:]*: *//' | cut -c1-300
}
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
HEAD_NO_DISPLAY=0
head_diag() {      # $1 = seconds waited
  local st loaded gpu out
  st=$(autogo_state)
  loaded=$(kmutil showloaded 2>/dev/null | grep -cE 'com\.nullmoth\.(NVRM|NVAccel|NVRMFB|NVRMAGDC)')
  gpu=$(ioreg -c IOPCIDevice -lw0 2>/dev/null | grep -cE '"vendor-id" = <de100000>')
  say "no head after $1 s: driver state '${st:-none published}', NullMoth graphics extensions running $loaded of 4, NVIDIA PCI functions $gpu, NVRM service $(ioreg -c NVRM 2>/dev/null | grep -c 'class NVRM'), NVAccel service $(ioreg -c NVAccel 2>/dev/null | grep -c 'class NVAccel'), heads sysctl '$(sysctl -n debug.nvaccel_heads_published 2>&1 | head -n 1)'"
  out=$(driver_lines 4m)
  if [ -z "$out" ]; then say "no head: the kernel log holds no driver line for this start (the query returned nothing - the driver may not have started, or the log could not be read)"
  else
    say "no head: the driver's last lines of this start:"
    printf '%s\n' "$out" | grep -E 'auto-go|go\(|display|head|FAILED|failed|error|chipset|GSP|not ' | tail -n 30 | sed 's/^/    /'
    printf '%s\n' "$out" | grep -q 'no display on any NVIDIA connector' && HEAD_NO_DISPLAY=1
  fi
  return 0
}
# A start with no head often comes up on the next start. Restart once by itself instead of leaving a black screen:
# only when nobody is logged in, only when the driver did not say that no display is connected to the card, and
# at most RECOVER_MAX times in a row (the count is cleared by the next healthy start).
head_restart() {
  local n who
  [ "$HEAD_NO_DISPLAY" = 1 ] && { say "no automatic restart: the driver reports no display on any NVIDIA connector"; return 1; }
  who=$(console_user)
  [ -n "$who" ] && { say "no automatic restart: a user session is active (${who})"; return 1; }
  n=$(cat "$RESTARTS" 2>/dev/null); case "$n" in ''|*[!0-9]*) n=0;; esac
  if [ "$n" -ge "$RECOVER_MAX" ]; then
    say "no automatic restart: restarted $n time(s) in a row for this already - it needs a person (read $LOG)"; return 1; fi
  echo $((n + 1)) > "$RESTARTS.tmp" && mv -f "$RESTARTS.tmp" "$RESTARTS" || { say "no automatic restart: the count could not be written"; return 1; }
  say "no display head this start: restarting the machine (automatic restart $((n + 1)) of $RECOVER_MAX)"
  restart_machine
}

wait_for_head() {
  local i st last_st="-"
  local seen=0 why
  for i in $(seq 1 "$HEAD_WAIT_TRIES"); do
    [ "$(heads)" -ge 1 ] && { say "NVAccel head published after ~$((i * 2)) s"; return 0; }
    if why=$(display_elsewhere); then seen=$((seen + 1)); else seen=0; fi
    if [ "$seen" -ge 3 ]; then
      HEAD_NO_DISPLAY=1
      say "no display on the NVIDIA card after ~$((i * 2)) s: $why - the screen is on that chip; no head is coming and no restart can bring one"
      return 2
    fi
    go2_retry && [ "$(heads)" -ge 1 ] && return 0
    st=$(autogo_state)
    [ "$st" = "$last_st" ] || { say "waiting for a head ($((i * 2)) s): driver state '${st:-none published}'"; last_st=$st; }
    [ "$i" = "$HEAD_DIAG_TRY" ] && head_diag $((i * 2))
    [ "$i" = "$HEAD_RESTART_TRY" ] && [ "$(heads)" -lt 1 ] && head_restart
    sleep 2
  done
  say "STOP: NVAccel published no head within $((HEAD_WAIT_TRIES * 2)) s - the screen stays on the software compositor"
  return 1
}

console_user() {
  local u s
  u=$(stat -f %Su /dev/console 2>/dev/null)
  s=$(who 2>/dev/null | awk '$2 == "console" {print $1; exit}')
  case "$u" in root|loginwindow) u="";; esac
  case "$s" in loginwindow) s="";; esac
  if [ -n "$u" ]; then echo "$u"; elif [ -n "$s" ]; then echo "$s"
  elif [ -z "$(stat -f %Su /dev/console 2>/dev/null)" ]; then echo unknown
  elif [ -n "$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)" ]; then echo "automatic login"; fi
}

on_pipe_already() {
  [ -f "$WSGATE_DONE" ] || return 1
  [ "$(tail -n 1 "$WSGATE_DONE" 2>/dev/null | cut -d' ' -f1)" = software ] && return 1
  grep -q "^armed" "$WSGATE_DONE" 2>/dev/null && return 0
  [ "$(tail -n 1 "$WSGATE_DONE" 2>/dev/null | cut -d' ' -f1)" = ready ]
}
switch_windowserver() {
  local old who
  old=$(pgrep -x WindowServer)
  if on_pipe_already; then
    say "ws-gate started WindowServer $old on the pipe - no restart"
    return 0
  fi
  who=$(console_user)       # read right before the restart, so a login during the steps above is seen
  if [ -n "$who" ]; then
    say "user session active (console user ${who}) - pipe switch deferred to the next boot; WindowServer $old kept on the software compositor"
    return 1
  fi
  say "display pipe published; restarting WindowServer $old onto the Metal pipe"
  [ -n "$old" ] && kill -9 $old
  return 0
}

arm_display() {
  local caps old ok0 ok1 fail last same p i verdict
  if on_pipe_already; then
    say "ws-gate $(grep -q "^armed" "$WSGATE_DONE" 2>/dev/null && echo "armed the pipe before WindowServer $(pgrep -x WindowServer) started" || echo "found the pipe armed and started WindowServer $(pgrep -x WindowServer) on it") - no re-arm, no restart"
    pipe_verdict
    return
  fi
  if [ "$(sysctl -n debug.nvaccelfb)" = 0 ]; then
    sysctl -w debug.nvaccelfb=1; sleep 1
    if [ "$(sysctl -n debug.nvaccelfb)" != 1 ]; then say "STOP: level 1 did not take - not arming further"; return 0; fi
    sysctl -w debug.nvaccelfb=4
  else
    say "nvaccelfb already $(sysctl -n debug.nvaccelfb) - NVRM armed it itself"
  fi
  sleep 2
  sysctl -w debug.nvrmfb_agdc_k5=1; sysctl -w debug.nvrmfb_agdc=1; sysctl -w debug.nvaccel_iop=1
  caps=$(ioreg -r -c NVAccel -d 1 -l 2>/dev/null | grep -c IOAccelDisplayPipeCapabilities)
  if [ "$caps" -lt 1 ]; then say "STOP: IOAccelDisplayPipeCapabilities not published - WindowServer NOT restarted"; return 0; fi
  defaults write /Library/Preferences/com.apple.CoreDisplay useIOP_onNVIDIA -bool true
  switch_windowserver || return 0
  pipe_verdict
}

iop() { sysctl -n "debug.nvaccel_iop_$1" 2>/dev/null; }   # the pipe's counters: ok (frames through it), fail

RESTARTS=/var/db/nullmoth-display-restarts
RECOVER_MAX=2
WS_STDERR=/var/log/nullmoth-ws-stderr.log
restart_machine() { /sbin/shutdown -r now; }
DEATH_RE='native rip [0-9a-f]* *\(_ZN2CA3OGL2SW|^a2x-stop: frame [0-3] native QuartzCore\+0x[0-9a-f]+ _ZN2CA3OGL2SW'
WS_WATCH_FROM=0
file_bytes() { local n=0; [ -f "$1" ] && n=$(wc -c < "$1" 2>/dev/null | tr -d ' '); case "$n" in ''|*[!0-9]*) n=0;; esac; echo "$n"; }
ws_output_since_watch() {
  local now; now=$(file_bytes "$WS_STDERR")
  if [ "$now" -ge "$WS_WATCH_FROM" ]; then tail -c +$((WS_WATCH_FROM + 1)) "$WS_STDERR" 2>/dev/null | tail -c 400000
  else tail -c 400000 "$WS_STDERR" 2>/dev/null; fi
}
recover_dead_display() {
  local n
  if ! ws_output_since_watch | grep -aqE "$DEATH_RE"; then
    say "no automatic restart: the window server's output does not show the no-display-pipe death"; return 1; fi
  n=$(cat "$RESTARTS" 2>/dev/null); case "$n" in ''|*[!0-9]*) n=0;; esac
  if [ "$n" -ge "$RECOVER_MAX" ]; then
    say "no automatic restart: restarted $n time(s) in a row for this already - it needs a person (read /var/log/nullmoth-ws-gate.log)"; return 1; fi
  echo $((n + 1)) > "$RESTARTS.tmp" && mv -f "$RESTARTS.tmp" "$RESTARTS" || { say "no automatic restart: the count could not be written"; return 1; }
  say "the window server found no display pipe this boot: restarting the machine (automatic restart $((n + 1)) of $RECOVER_MAX)"
  restart_machine
}

pipe_verdict() {
  local ok0 fail0 ok1 fail1 last="" same=0 p i
  ok0=$(iop ok); fail0=$(iop fail); ok0=${ok0:-0}; fail0=${fail0:-0}
  WS_WATCH_FROM=$(file_bytes "$WS_STDERR")
  for i in $(seq 1 20); do
    sleep 3; p=$(pgrep -x WindowServer | head -1)
    if [ -n "$p" ] && [ "$p" = "$last" ]; then same=$((same+1)); else same=0; last="$p"; fi
    [ $same -ge 10 ] && break
  done
  if [ $same -lt 10 ]; then
    say "NOT healthy (WindowServer never held one pid for 30 s in 60 s) - flip left off; read /var/log/nullmoth-ws-stderr.log"
    recover_dead_display
    return 1
  fi
  for i in $(seq 0 "$IDLE_WATCH_TRIES"); do
    [ "$i" = 0 ] || sleep 3
    ok1=$(iop ok); fail1=$(iop fail); ok1=${ok1:-0}; fail1=${fail1:-0}
    p=$(pgrep -x WindowServer | head -1)
    if [ "$p" != "$last" ]; then
      say "NOT healthy: WindowServer $last went away (now ${p:-none}); frames through our pipe $((ok1-ok0)) (fail $((fail1-fail0))) - flip left off; read /var/log/nullmoth-ws-stderr.log"
      return 1
    fi
    if [ "$fail1" -gt "$fail0" ]; then
      say "NOT healthy: $((fail1-fail0)) frame(s) failed through our pipe (ok $((ok1-ok0))) - flip left off; read /var/log/nullmoth-ws-stderr.log"
      return 1
    fi
    if [ "$ok1" -gt "$ok0" ]; then
      sysctl -w debug.nvaccel_iop_flip=1
      pipe_final "flip on"
      rm -f "$RESTARTS"
      say "HEALTHY: WindowServer $last steady, frames through our pipe $((ok1-ok0)) (fail 0)$([ "$i" = 0 ] || echo " after $((i * 3)) s idle"); async flip on"
      return 0
    fi
  done
  say "steady but idle: WindowServer $last drew no frame in $((30 + IDLE_WATCH_TRIES * 3)) s (fail 0) - flip left off"
  return 1
}

pipe_final() {
  [ -e "$PIPE_DONE" ] && return 0
  echo "final $(date '+%T') $*" > "$PIPE_DONE.tmp" && mv -f "$PIPE_DONE.tmp" "$PIPE_DONE"
}

cap_log() {
  local f=$1 n
  n=$(stat -f %z "$f" 2>/dev/null) || return 0
  [ "$n" -gt 1048576 ] || return 0
  tail -c 524288 "$f" > "$f.cap" 2>/dev/null && cat "$f.cap" > "$f"; rm -f "$f.cap"
}
nvload_main() {
  if [ "$(cat /Library/NullMoth/bringup/graphics-path 2>/dev/null)" = apple ]; then
    say "graphics path is apple: nothing to do for the NVIDIA pipe"; return 0
  fi
  cap_log "$LOG"
  exec >> "$LOG" 2>&1
  say "== nvload start, boot $(sysctl -n kern.boottime | cut -c1-40)"
  wait_for_head; local wr=$?
  if [ "$wr" = 2 ]; then
    # The window server starts on the other chip's screen (ws-gate). Healthy = it keeps one process id for 2 minutes.
    local p0 p n=0 t=0
    while [ $t -lt 150 ]; do
      t=$((t + 1))
      p=$(pgrep -x WindowServer | head -n 1)
      if [ -n "$p" ] && [ "$p" = "$p0" ]; then [ $n -ge 60 ] && { say "HEALTHY: the desktop is on the other graphics chip's screen (WindowServer $p steady 2 min); NVIDIA has no display"; pipe_final "display elsewhere"; exit 0; }
      else p0=$p; n=0; fi
      sleep 2; n=$((n + 1))
    done
    say "the window server did not stay up on the other graphics chip's screen in 5 min"
    pipe_final "display elsewhere, not steady"; exit 0
  fi
  if [ "$wr" != 0 ]; then pipe_final "no head"; exit 0; fi
  arm_display
  pipe_final "done"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    "") nvload_main;;
    *) echo "usage: nvload.sh" >&2; exit 2;;
  esac
fi

