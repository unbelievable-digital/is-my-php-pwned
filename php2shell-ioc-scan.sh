#!/usr/bin/env bash
# php2shell-ioc-scan.sh — read-only compromise/IoC scanner for PHP servers
# Context: CVE-2026-109618 / CVE-2026-109619 ("php2shell"), unauthenticated RCE.
# This script does NOT exploit anything. It only reads files, logs and process
# state to surface post-exploitation indicators so an operator can triage.
#
# Usage:  sudo bash php2shell-ioc-scan.sh [--days N] [--webroot DIR] [--json]
# Exit:   0 clean-ish, 1 findings worth review, 2 error. Nothing is modified.
#
# License: MIT. Share freely.
set -u
DAYS=7
WEBROOTS=()
JSON=0
FINDINGS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="${2:-7}"; shift 2;;
    --webroot) WEBROOTS+=("${2:-}"); shift 2;;
    --json) JSON=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

c_red=$'\e[31m'; c_yel=$'\e[33m'; c_grn=$'\e[32m'; c_dim=$'\e[2m'; c_rst=$'\e[0m'
[ -t 1 ] || { c_red=; c_yel=; c_grn=; c_dim=; c_rst=; }

note(){ printf '%s[ ok ]%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn(){ FINDINGS=$((FINDINGS+1)); printf '%s[WARN]%s %s\n' "$c_yel" "$c_rst" "$*"; }
crit(){ FINDINGS=$((FINDINGS+1)); printf '%s[CRIT]%s %s\n' "$c_red" "$c_rst" "$*"; }
hdr(){ printf '\n%s== %s%s\n' "$c_dim" "$*" "$c_rst"; }

echo "php2shell IoC scan — host=$(hostname) date=$(date -u +%FT%TZ) lookback=${DAYS}d"

# ---- 0. discover web roots if not given --------------------------------------
if [ "${#WEBROOTS[@]}" -eq 0 ]; then
  mapfile -t WEBROOTS < <(
    { nginx -T 2>/dev/null | grep -oP '(?<=root\s)[^;]+';
      grep -rhoP '(?<=DocumentRoot\s)\S+' /etc/apache2 2>/dev/null;
      grep -rhoP '(?<=docRoot\s)\S+' /usr/local/lsws/conf 2>/dev/null;
      grep -rhoP '(?<=root \* )\S+' /etc/frankenphp 2>/dev/null;
    } | tr -d '"' | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done
  )
  [ "${#WEBROOTS[@]}" -eq 0 ] && WEBROOTS=(/var/www)
fi
hdr "web roots"; printf '  %s\n' "${WEBROOTS[@]}"

# ---- 1. installed PHP version vs fixed ---------------------------------------
hdr "PHP version vs fixed (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; <=8.1 EOL)"
ver_vuln(){ # $1=maj.min $2=patch -> echo VULN/OK/EOL
  local b="$1" p="$2"
  case "$b" in
    8.5) [ "$p" -ge 12 ] && echo OK || echo VULN;;
    8.4) [ "$p" -ge 27 ] && echo OK || echo VULN;;
    8.3) [ "$p" -ge 36 ] && echo OK || echo VULN;;
    8.2) [ "$p" -ge 35 ] && echo OK || echo VULN;;
    *) echo EOL;;
  esac
}
for bin in $(ls /usr/sbin/php-fpm* /usr/local/lsws/lsphp*/bin/php /usr/local/bin/frankenphp 2>/dev/null); do
  case "$bin" in
    *frankenphp) full=$("$bin" php-cli -r 'echo PHP_VERSION;' 2>/dev/null);;
    *) full=$("$bin" -v 2>/dev/null | grep -oP '(?<=^PHP )\d+\.\d+\.\d+' | head -1);;
  esac
  full=$(printf '%s' "$full" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -z "$full" ] && continue
  base=${full%.*}; patch=${full##*.}; patch=${patch%%[-~ ]*}
  st=$(ver_vuln "$base" "$patch")
  case "$st" in
    OK) note "$bin -> PHP $full (patched)";;
    EOL) crit "$bin -> PHP $full (END-OF-LIFE, no fix will ship — must upgrade)";;
    *) crit "$bin -> PHP $full (VULNERABLE to php2shell — patch now)";;
  esac
done

# ---- 2. recently written/modified executable PHP in web roots ----------------
hdr "PHP files created/changed in web roots within ${DAYS}d (webshell candidates)"
recent=$(find "${WEBROOTS[@]}" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \) \
          -mtime "-${DAYS}" 2>/dev/null)
if [ -n "$recent" ]; then
  while IFS= read -r f; do warn "recent PHP: $f ($(date -r "$f" -u +%FT%TZ 2>/dev/null))"; done <<<"$recent"
else note "no PHP files modified in last ${DAYS}d"; fi

# ---- 3. webshell / obfuscation signatures ------------------------------------
# Two tiers: HIGH-confidence shell markers (rare in legit code) are always loud.
# Generic markers (base64_decode/eval, common in vendored libs) are only loud
# when the file also changed within the lookback window, to cut false positives
# from PHPMailer, WordPress core, Composer vendor trees, etc.
hdr "webshell signatures in web roots"
VENDOR='/(vendor|node_modules|wp-includes|wp-admin)/'
pat_high='c99shell|r57shell|c99madshell|b374k|FilesMan|WSO [0-9]|ALFA.?SHELL|IndoXploit|0byt3m1n1|str_rot13\s*\(\s*base64_decode|\$_(GET|POST|REQUEST|COOKIE)\s*\[[^]]*\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|(eval|assert|system|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\(\s*\$'
pat_gen='eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|\bsystem\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\('
found=0
while IFS= read -r f; do [ -z "$f" ] && continue; found=1; crit "HIGH-confidence shell marker: $f"; done < <(
  grep -rslEI "$pat_high" "${WEBROOTS[@]}" --include='*.php' --include='*.phtml' 2>/dev/null)
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if [ -n "$(find "$f" -mtime "-${DAYS}" 2>/dev/null)" ]; then found=1
    case "$f" in *$VENDOR*) warn "generic marker in recently-changed vendor file: $f";; *) crit "generic marker + recently changed: $f";; esac
  fi
done < <(grep -rslEI "$pat_gen" "${WEBROOTS[@]}" --include='*.php' --include='*.phtml' 2>/dev/null \
         | grep -vE "$VENDOR")
[ "$found" -eq 0 ] && note "no high-confidence or recently-changed shell signatures"

# ---- 4. world-writable / odd-owner PHP in web roots --------------------------
hdr "writable or suspicious-owner PHP files"
find "${WEBROOTS[@]}" -type f -name '*.php' -perm -o+w 2>/dev/null | while read -r f; do warn "world-writable PHP: $f"; done

# ---- 5. PHP-FPM / web OOM & segfault crashes (exploit attempt footprint) -----
hdr "FPM/segfault/OOM footprints in last ${DAYS}d (php2shell relies on OOM/stale state)"
if command -v journalctl >/dev/null 2>&1; then
  n=$(journalctl --since "-${DAYS} days" 2>/dev/null | grep -icE 'php-fpm.*(SIGSEGV|segfault|child.*exited on signal|out of memory)|frankenphp.*(SIGSEGV|panic)')
  [ "${n:-0}" -gt 0 ] && warn "journal shows $n php-fpm/frankenphp crash/OOM lines (review: journalctl | grep -iE 'php-fpm.*signal|segfault')" || note "no FPM crash/OOM lines in journal"
fi
for lg in /var/log/php*-fpm.log /usr/local/lsws/logs/*.log; do
  [ -f "$lg" ] || continue
  m=$(grep -icE 'SIGSEGV|segfault|exited on signal|oom' "$lg" 2>/dev/null)
  [ "${m:-0}" -gt 0 ] && warn "$lg: $m crash/OOM lines"
done

# ---- 6. suspicious running processes -----------------------------------------
hdr "suspicious processes (reverse shells / miners spawned from web user)"
ps -eo user,pid,ppid,comm,args 2>/dev/null | grep -iE \
  'bash -i|sh -i|/dev/tcp/|nc .* -e|ncat .* -e|python.* -c .*socket|perl .*socket|xmrig|minerd|kinsing|/tmp/\.|curl .*\|.*sh|wget .*\|.*sh' \
  | grep -vE 'grep|php2shell-ioc' | while read -r l; do crit "process: $l"; done
note "process scan done"

# ---- 7. outbound listeners / unexpected binds --------------------------------
hdr "listening sockets owned by web/php users"
if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null | grep -iE 'php|www-data|nobody' | while read -r l; do warn "listener by web user: $l"; done
  note "socket scan done"
fi

# ---- 8. persistence: cron & authorized_keys recently touched -----------------
hdr "persistence surfaces (cron, authorized_keys) changed in ${DAYS}d"
for p in /etc/crontab /etc/cron.d /var/spool/cron /var/spool/cron/crontabs; do
  [ -e "$p" ] && find "$p" -mtime "-${DAYS}" -type f 2>/dev/null | while read -r f; do warn "cron changed: $f"; done
done
find /root /home -maxdepth 4 -name authorized_keys -mtime "-${DAYS}" 2>/dev/null | while read -r f; do crit "authorized_keys changed: $f"; done
find /var/www /home -maxdepth 6 -type f \( -name '*.php' -o -name '*.sh' \) -newermt "-${DAYS} days" -path '*upload*' 2>/dev/null | while read -r f; do warn "recent file under upload dir: $f"; done

# ---- summary -----------------------------------------------------------------
echo
if [ "$FINDINGS" -eq 0 ]; then
  printf '%sSUMMARY: no indicators found. Not proof of safety — patch PHP regardless.%s\n' "$c_grn" "$c_rst"
  exit 0
else
  printf '%sSUMMARY: %d indicator(s) to review above. Triage before trusting the host.%s\n' "$c_yel" "$FINDINGS" "$c_rst"
  exit 1
fi
