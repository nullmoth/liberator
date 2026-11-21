#!/bin/bash
# Keeps the redirect of Apple silicon programs to the interpreter switched on while the system is healthy,
# and switches it off when programs are started faster than the limit below.
set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

EVERY=20                       # keepalive period, well inside the dead-man window
DEADMAN=120
# Stock 27: the kernel armed the hook at boot (a2xbootarm=1), so Apple's arm64-only files need it until power-off.
STOCK=0; [ "$(sysctl -n a2x.exec_hook_bootarm_result 2>/dev/null)" = "0" ] && STOCK=1
[ "$STOCK" = 1 ] && DEADMAN=3600
MAX_PER_MIN=150                # programs started through the interpreter per minute before the redirect is switched off

say() { printf '%s a2x-keepalive: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
KLOG=/var/log/a2x-keepalive.log
if [ "$(stat -f %z "$KLOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 524288 "$KLOG" > "$KLOG.cap" 2>/dev/null && cat "$KLOG.cap" > "$KLOG"; rm -f "$KLOG.cap"; fi

if ! sysctl -n a2x.exec_hook_verified >/dev/null 2>&1; then
    say "REFUSE: no a2x.* sysctls - the exec hook kext is not loaded. Nothing to arm."
    exit 1
fi
v=$(sysctl -n a2x.exec_hook_verified 2>/dev/null)
if [ "$v" != "1" ]; then
    say "REFUSE: exec_hook_verified=$v - the kext did not verify this kernel, so it would refuse to arm."
    say "        Read: log show --last 10m --predicate 'eventMessage CONTAINS \"a2x-exec-hook\"'"
    exit 1
fi

for host in /usr/libexec/a2x/a2xhost /usr/libexec/a2x/a2xlaunch /usr/libexec/a2x/a2xhost-cat /usr/libexec/a2x/a2xhost-mac; do
    if [ ! -f "$host" ] || [ ! -x "$host" ]; then
        say "REFUSE: required runtime executable unavailable: $host"
        exit 1
    fi
done
if [ ! -f /usr/libexec/a2x/a2xpre.dylib ] || [ ! -r /usr/libexec/a2x/a2xpre.dylib ]; then
    say "REFUSE: required pre-init library unavailable: /usr/libexec/a2x/a2xpre.dylib"
    exit 1
fi
if ! sysctl -n a2xa.adopt_enable >/dev/null 2>&1; then
    say "REFUSE: adoption node unavailable; runtime identity cannot be established"
    exit 1
fi
if ! sysctl -w a2xa.adopt_enable=1 >/dev/null 2>&1 ||
   [ "$(sysctl -n a2xa.adopt_enable 2>/dev/null)" != "1" ]; then
    say "REFUSE: adoption enable failed or readback was not 1"
    exit 1
fi
say "adoption ready before exec arming"
if ! sysctl -w a2x.exec_hook_deadman_secs=$DEADMAN >/dev/null 2>&1 ||
   [ "$(sysctl -n a2x.exec_hook_deadman_secs 2>/dev/null)" != "$DEADMAN" ]; then
    say "REFUSE: dead-man configuration failed or readback did not match $DEADMAN"
    exit 1
fi
prev=$(sysctl -n a2x.exec_claimed 2>/dev/null) || {
    say "REFUSE: initial claim counter read failed"
    exit 1
}
case "$prev" in
    ''|*[!0-9]*) say "REFUSE: initial claim counter is not an unsigned integer"; exit 1;;
esac
prev_time=$SECONDS
if ! sysctl -w a2x.exec_hook_enable=1 >/dev/null 2>&1 ||
   [ "$(sysctl -n a2x.exec_hook_enable 2>/dev/null)" != "1" ]; then
    say "REFUSE: arming failed or readback was not 1"
    exit 1
fi
if ! sysctl -w a2x.exec_hook_keepalive=1 >/dev/null 2>&1; then
    say "REFUSE: initial heartbeat failed; disarming"
    sysctl -w a2x.exec_hook_enable=0 >/dev/null 2>&1
    exit 1
fi
say "runtime prerequisites ready; armed, heartbeat every ${EVERY}s against a ${DEADMAN}s dead-man"

# The Apple board name Software Update reports. It is set here, after start-up, so the drivers that took their
# settings from the firmware's board name keep them. No file or no switch in the kext: nothing is changed.
BOARD=$(head -c 16 /Library/NullMoth/a2x/board 2>/dev/null | tr -cd 'A-Za-z0-9-')
if [ -n "$BOARD" ] && sysctl -n a2x.board_id >/dev/null 2>&1; then
    if sysctl -w a2x.board_id="$BOARD" >/dev/null 2>&1 && [ "$(sysctl -n a2x.board_id 2>/dev/null)" = "$BOARD" ]; then
        say "board name for Software Update: $BOARD"
        # The update services read the name once, when they start, and they start before this runs.
        for svc in com.apple.mobileassetd com.apple.softwareupdated; do
            /bin/launchctl kickstart -k system/$svc >/dev/null 2>&1 || say "could not restart $svc; Software Update may show nothing until the next start"
        done
    else
        say "board name $BOARD was not accepted"
    fi
fi

if [ "$(sysctl -n a2xa.adopt_enable 2>/dev/null)" = "1" ]; then
    if /usr/bin/notifyutil -p com.apple.oah.did-install; then
        say "runtime availability announced; pending executable events rechecked"
    else
        say "runtime availability notification failed; pending executables may remain deferred"
    fi
fi
CHG=/usr/local/lib/nullmoth/charging-init.dylib
CHG_SHA=fb85e81074793f628eb7252a1fbec66059cd5b57cbee093f7f2c31706520959b
if [ -f "$CHG" ] && [ "$(/usr/bin/shasum -a 256 "$CHG" | awk '{print $1}')" = "$CHG_SHA" ]; then
    if /bin/launchctl print system/com.apple.ospredictiond 2>/dev/null | grep -A3 '"com.apple.OSIntelligence.charging"' | grep -q 'active = 1'; then
        say "charging listener already active"
    elif /bin/launchctl debug system/com.apple.ospredictiond --environment DYLD_INSERT_LIBRARIES="$CHG" </dev/null >/dev/null 2>&1; then
        p=$(/usr/bin/pgrep -x ospredictiond); [ -n "$p" ] && kill -9 $p
        say "charging listener: ospredictiond relaunch with charging-init (was pid ${p:-none})"
    else
        say "charging listener: launchctl debug FAILED; dasd may wedge"
    fi
else
    say "charging listener: $CHG missing or wrong sha; dasd may wedge"
fi
beats=0
while :; do
    en=$(sysctl -n a2x.exec_hook_enable 2>/dev/null)
    if [ "$en" != "1" ]; then
        say "DISARMED under us: enable=${en:-?} deadman_fired=$(sysctl -n a2x.exec_hook_deadman_fired 2>/dev/null) load=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}') - exiting to re-arm"
        exit 1
    fi
    if ! sysctl -w a2x.exec_hook_keepalive=1 >/dev/null 2>&1; then
        say "keepalive write FAILED - exiting so the dead-man disarms the kernel"
        exit 1
    fi

    now=$(sysctl -n a2x.exec_claimed 2>/dev/null); now=${now:-$prev}
    now_time=$SECONDS
    elapsed=$((now_time - prev_time))
    [ "$elapsed" -ge "$EVERY" ] || elapsed=$EVERY
    rate=$(( (now - prev) * 60 / elapsed ))
    prev=$now
    prev_time=$now_time
    # stock 27: a busy minute is the system's own programs, never a reason to disarm
    if [ "$STOCK" = 1 ] && [ "$rate" -gt "$MAX_PER_MIN" ]; then
        say "busy: ${rate} execs/min (stock 27, not disarming) claimed=$now"
    elif [ "$rate" -gt "$MAX_PER_MIN" ]; then
        say "STORM: ${rate} execs/min exceeds ${MAX_PER_MIN} - DISARMING (claimed=$now)"
        say "       the arm64 programs stop running; everything that ran before the hook is unaffected"
        sysctl -w a2x.exec_hook_enable=0 >/dev/null 2>&1
        exit 1
    fi

    say "ok rate=${rate}/min claimed=$now"

    beats=$((beats + 1))
    if [ "$beats" -le $((300 / EVERY)) ]; then
        /usr/bin/notifyutil -p com.apple.oah.did-install && say "runtime availability re-announced (beat ${beats})"
    fi
    sleep $EVERY
done

