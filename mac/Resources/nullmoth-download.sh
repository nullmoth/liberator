#!/bin/bash
# Download a file of known size. Keep a contiguous prefix at the original path
# so retries, the kit's progress watches, and curl -C - all see the same file.

nm_download_size() {
  if [ -f "$1" ]; then /usr/bin/stat -f %z "$1"; else printf '0\n'; fi
}

nm_range_curl() {
  local url=$1 protocol=$2 range=$3 bytes=$4 piece=$5
  shift 5
  exec /usr/bin/curl -q -fsSL --proto "$protocol" --proto-redir "$protocol" \
    --header 'Accept-Encoding: identity' --range "$range" --max-filesize "$bytes" \
    --connect-timeout 15 --dump-header "$piece.headers" --write-out '%{http_code}' -o "$piece" "$@" "$url"
}

nm_range_matches() {
  local piece=$1 range=$2 total=$3 bytes=$4
  [ "$(cat "$piece.status")" = 206 ] && [ "$(nm_download_size "$piece")" = "$bytes" ] &&
    awk -v expected="bytes $range/$total" '
      /^HTTP\// { got = "" }
      tolower($0) ~ /^content-range:/ {
        got = $0
        sub(/^[^:]*:[[:space:]]*/, "", got)
        sub(/[[:space:]]+$/, "", got)
      }
      END { exit(tolower(got) != expected) }
    ' "$piece.headers"
}

nm_wait_for_curl() {
  local pid=$1 status=0
  wait "$pid" || status=$?
  pending=${pending#"$pid "}
  return "$status"
}

nm_download_ranges() {
  local url=$1 file=$2 total=$3 protocol=$4 have=$5
  local min_chunk=$((1024 * 1024)) max_window=$((256 * 1024 * 1024))
  local workers window start end count part i
  local starts ends pids
  case "$protocol" in '=https'|'=http') ;; *) return 1;; esac
  [ "$((total - have))" -ge "$((16 * min_chunk))" ] || return 1
  workers=$(/usr/sbin/sysctl -n hw.logicalcpu 2>/dev/null) || return 1
  case "$workers" in ''|*[!0-9]*) return 1;; esac
  [ "$workers" -gt 1 ] || return 1
  scratch=$(mktemp -d "$(dirname "$file")/.download.XXXXXXXX") || return 1

  # A one-byte GET proves Range support through redirects without trusting HEAD
  # or Accept-Ranges. A successful 200 still goes to the normal curl path.
  (nm_range_curl "$url" "$protocol" "$have-$have" 1 "$scratch/probe" --max-time 20) >"$scratch/probe.status" 2>/dev/null &
  pending="$! "
  if ! { nm_wait_for_curl "$!" && nm_range_matches "$scratch/probe" "$have-$have" "$total" 1; }; then
    [ "$(cat "$scratch/probe.status")" != 200 ] || restart=1
    return 1
  fi
  printf 'NOTE downloading in up to %s parallel connections\n' "$workers"

  while [ "$have" -lt "$total" ]; do
    window=$((total - have))
    [ "$window" -le "$max_window" ] || window=$max_window
    count=$(((window + min_chunk - 1) / min_chunk))
    [ "$count" -le "$workers" ] || count=$workers
    for ((i = 0; i < count; i++)); do
      start=$((have + window * i / count))
      end=$((have + window * (i + 1) / count - 1))
      part="$scratch/part.$i"
      (nm_range_curl "$url" "$protocol" "$start-$end" "$((end - start + 1))" "$part" \
        --retry 2 --retry-delay 1 --speed-limit 1024 --speed-time 45 --max-time 300) >"$part.status" 2>/dev/null &
      pids[$i]=$!
      pending="$pending$! "
      starts[$i]=$start
      ends[$i]=$end
    done
    # Append only checked ranges, in order. The window bounds temporary disk
    # space, and an interrupted append still leaves bytes curl can resume from.
    for ((i = 0; i < count; i++)); do
      part="$scratch/part.$i"
      start=${starts[$i]}
      end=${ends[$i]}
      nm_wait_for_curl "${pids[$i]}" && nm_range_matches "$part" "$start-$end" "$total" "$((end - start + 1))" || return 1
      cat "$part" >> "$file" || return 1
      rm -f "$part"
      have=$((end + 1))
    done
  done
}

nm_download_cleanup() {
  local pid
  for pid in $pending; do kill "$pid" 2>/dev/null || :; done
  for pid in $pending; do wait "$pid" 2>/dev/null || :; done
  pending=""
  [ -z "$scratch" ] || rm -rf "$scratch"
  scratch=""
}

nm_download() (  # URL FILE pinned-size protocol followed by the original curl options and URL
  local url=$1 file=$2 total=$3 protocol=$4 have rc scratch="" pending="" restart=0
  shift 4
  umask 077
  case "$total" in ''|*[!0-9]*) return 1;; esac
  [ ! -L "$file.download-lock" ] && { [ ! -e "$file.download-lock" ] || [ -f "$file.download-lock" ]; } || return 1
  # lockf on an inherited descriptor keeps the lock for this subshell. Concurrent
  # downloads must not append to the same prefix or restart it under another run.
  exec 9>>"$file.download-lock" || return 1
  if ! /usr/bin/lockf -s -t 0 9; then
    echo "NOTE another download is using $file"
    return 75
  fi
  [ ! -L "$file" ] && { [ ! -e "$file" ] || [ -f "$file" ]; } || return 1
  have=$(nm_download_size "$file") || return 1
  [ "$have" -le "$total" ] || return 1
  [ "$have" -lt "$total" ] || return 0

  trap nm_download_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  if nm_download_ranges "$url" "$file" "$total" "$protocol" "$have"; then return 0; fi
  [ -z "$scratch" ] || echo "NOTE parallel download unavailable, continuing with one connection"
  nm_download_cleanup

  # Run the original transfer under the same lock. If this server explicitly
  # rejects resuming a partial file, restart once from byte zero.
  if [ "$restart" = 1 ] && [ "$have" -gt 0 ]; then
    echo "NOTE the server does not support resuming this download, restarting it"
    : > "$file" || return 1
  fi
  /usr/bin/curl -q "$@" &
  pending="$! "
  if nm_wait_for_curl "$!"; then
    [ "$(nm_download_size "$file")" = "$total" ]
    return $?
  else
    rc=$?
  fi
  [ "$rc" -eq 33 ] && [ "$(nm_download_size "$file")" -gt 0 ] || return "$rc"
  echo "NOTE the server does not support resuming this download, restarting it"
  : > "$file" || return 1
  /usr/bin/curl -q "$@" &
  pending="$! "
  nm_wait_for_curl "$!" && [ "$(nm_download_size "$file")" = "$total" ]
)

# The official kit archive stays pinned byte for byte. Only the two known
# resume commands in its lay-down scripts use this adapter. HEAD probes,
# downloads of keys, and future command forms still go to system curl.
nm_enable_kit_downloads() {
  curl() {
    local url="" file="" size=""
    case "${0##*/}" in
      lay-down-27.sh) url=${IPSW_URL:-}; file=${IPSW:-}; size=${IPSW_SIZE:-};;
      make-kernel-collections.sh) url=${KDK_URL:-}; file=${KDK:-}; size=${KDK_SIZE:-};;
    esac
    if [ "$#" -eq 23 ] && [ -n "$file" ] && [ -n "$size" ] && [[ "$url" = https://* ]] &&
       [ "$1 $2 $3 $4 $5 $6 $7 $8 $9 ${10}" = '-sS -f -L -C - --proto =https --proto-redir =https -o' ] &&
       [ "${11}" = "$file" ] && [ "${23}" = "$url" ] &&
       [ "${12} ${13} ${14} ${16} ${17} ${18} ${19} ${20} ${21} ${22}" = \
         '--connect-timeout 30 --retry --retry-delay 5 --retry-all-errors --speed-limit 1024 --speed-time 120' ] &&
       { [ "${15}" = 50 ] || [ "${15}" = 100 ]; }; then
      nm_download "$url" "$file" "$size" '=https' "$@"
    else
      /usr/bin/curl -q "$@"
    fi
  }
}
