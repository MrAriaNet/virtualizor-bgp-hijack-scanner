#!/usr/bin/env bash
#===============================================================================
#  virtualizor-bgp-hijack-scan.sh
#
#  Detection and triage scanner for the Virtualizor / Softaculous supply-chain
#  compromise that was delivered through the BGP hijack of 162.55.80.0/24
#  between 2026-08-28 20:57 UTC and 2026-08-30 06:10 UTC.
#
#  During that window a malicious "Virtualizor 3.2.9.8" update package could be
#  served to any installation whose update check was routed to the attacker.
#  The package injected @exec() calls into legitimate Virtualizor files,
#  installed an attacker SSH key for root, fetched a Java RAT and registered the
#  systemd unit "java-jre-update.service" for persistence.
#
#  This script is READ-ONLY BY DESIGN. It never deletes, kills, disables or
#  "cleans" anything, because the vendor asks operators to preserve evidence and
#  contact support before remediating an affected host. It also performs no
#  outbound network connections.
#
#  Reference: https://www.virtualizor.com/blog/security-incident-bgp-hijacking/
#
#  SPDX-License-Identifier: MIT
#===============================================================================

set -uo pipefail

readonly SCRIPT_NAME="virtualizor-bgp-hijack-scan.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly ADVISORY_URL="https://www.virtualizor.com/blog/security-incident-bgp-hijacking/"
readonly SUPPORT_URL="https://softaculous.deskuss.com"
readonly FIXED_VERSION="3.2.9.9"

# Incident window as published by the vendor (UTC).
WINDOW_START="2026-08-28 20:57:00 UTC"
WINDOW_END="2026-08-30 06:10:00 UTC"

#-------------------------------------------------------------------------------
# Indicators of compromise
#-------------------------------------------------------------------------------

# Presence of any of these files is a confirmed indicator.
readonly IOC_FILES=(
    "/etc/systemd/system/java-jre-update.service"
    "/usr/lib/jvm/.cache/jre-runtime.dat"
    "/usr/lib/jvm/.cache/.installed"
    "/tmp/widdow.jar"
    "/tmp/.vz_svc_done"
)

readonly IOC_SERVICE="java-jre-update.service"
readonly IOC_PAYLOAD="/usr/lib/jvm/.cache/jre-runtime.dat"
readonly IOC_PAYLOAD_SHA256="b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"

# Attacker infrastructure.
readonly IOC_IPS=(
    "31.77.220.138"   # C2 endpoint, port 2025
    "193.32.127.248"  # source of the interactive SSH session into proxyuser
)
readonly IOC_DOMAINS=(
    "cdn.nerat.cc"
    "connect.ne-rat.xyz"
    "ne-rat.xyz"
)

# Attacker SSH public key added to root's authorized_keys.
readonly IOC_SSH_KEY_BODY="AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte"
readonly IOC_SSH_FINGERPRINT="SHA256:YQmy1hKF1h5cdJLxlZ5EScNoxe/UDWahjsWuQw2ERi8"

readonly IOC_ACCOUNT="proxyuser"

# Single regex used for content sweeps.
readonly IOC_REGEX='cdn\.nerat\.cc|widdow\.jar|jre-runtime\.dat|connect\.ne-rat\.xyz|ne-rat\.xyz|31\.77\.220\.138|193\.32\.127\.248|\.vz_svc_done|AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte'

# Virtualizor files the attacker is known to have modified.
readonly VZ_CORE_FILES=(
    "/usr/local/virtualizor/globals.php"
    "/usr/local/virtualizor/_universal.php"
    "/usr/local/virtualizor/zzvirtservice"
    "/etc/init.d/zzvirtservice"
)

readonly VZ_ROOT="/usr/local/virtualizor"

# Directories swept for IoC strings during a standard scan.
readonly SWEEP_DIRS=(
    "/usr/local/virtualizor"
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
    "/etc/init.d"
    "/root"
    "/tmp"
    "/var/tmp"
    "/usr/lib/jvm"
)

#-------------------------------------------------------------------------------
# Runtime options
#-------------------------------------------------------------------------------

OPT_QUIET=0
OPT_COLOR="auto"
OPT_JSON_FILE=""
OPT_REPORT_FILE=""
OPT_EVIDENCE_DIR=""
OPT_FULL_FS_SCAN=0

SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
readonly SELF_PATH

#-------------------------------------------------------------------------------
# Finding storage
#-------------------------------------------------------------------------------

readonly FS=$'\x1f'  # field separator inside a finding record

FINDINGS=()
COUNT_CRITICAL=0
COUNT_WARNING=0
COUNT_INFO=0

VIRTUALIZOR_DETECTED="false"
VIRTUALIZOR_VERSION="unknown"
SCAN_STARTED=""
SCAN_FINISHED=""

C_RESET=""; C_BOLD=""; C_DIM=""
C_RED=""; C_YELLOW=""; C_GREEN=""; C_BLUE=""; C_CYAN=""

setup_colors() {
    local enable=0
    case "$OPT_COLOR" in
        always) enable=1 ;;
        never)  enable=0 ;;
        auto)   [ -t 1 ] && enable=1 ;;
    esac
    if [ "$enable" -eq 1 ]; then
        C_RESET=$'\033[0m';  C_BOLD=$'\033[1m';    C_DIM=$'\033[2m'
        C_RED=$'\033[31m';   C_YELLOW=$'\033[33m'; C_GREEN=$'\033[32m'
        C_BLUE=$'\033[34m';  C_CYAN=$'\033[36m'
    fi
}

#-------------------------------------------------------------------------------
# Output helpers
#-------------------------------------------------------------------------------

section() {
    [ "$OPT_QUIET" -eq 1 ] && return 0
    printf '\n%s%s>> %s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"
}

say_ok()   { [ "$OPT_QUIET" -eq 1 ] || printf '   %s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
say_info() { [ "$OPT_QUIET" -eq 1 ] || printf '   %s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
say_warn() { [ "$OPT_QUIET" -eq 1 ] || printf '   %s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
say_crit() { [ "$OPT_QUIET" -eq 1 ] || printf '   %s%s[CRIT]%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$*"; }
say_skip() { [ "$OPT_QUIET" -eq 1 ] || printf '   %s[SKIP]%s %s\n' "$C_DIM" "$C_RESET" "$*"; }

# add_finding <severity: critical|warning|info> <id> <title> <detail>
add_finding() {
    local severity="$1" id="$2" title="$3" detail="${4:-}"
    FINDINGS+=("${severity}${FS}${id}${FS}${title}${FS}${detail}")
    case "$severity" in
        critical) COUNT_CRITICAL=$((COUNT_CRITICAL + 1)); say_crit "${title}${detail:+ -- $detail}" ;;
        warning)  COUNT_WARNING=$((COUNT_WARNING + 1));   say_warn "${title}${detail:+ -- $detail}" ;;
        info)     COUNT_INFO=$((COUNT_INFO + 1));         say_info "${title}${detail:+ -- $detail}" ;;
    esac
}

#-------------------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

sha256_of() {
    local file="$1"
    if have sha256sum; then
        sha256sum -- "$file" 2>/dev/null | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 -- "$file" 2>/dev/null | awk '{print $1}'
    elif have openssl; then
        openssl dgst -sha256 "$file" 2>/dev/null | awk '{print $NF}'
    fi
}

file_meta() {
    local file="$1"
    if have stat; then
        stat -c 'size=%s owner=%U:%G mode=%a mtime=%y' -- "$file" 2>/dev/null && return 0
    fi
    ls -l -- "$file" 2>/dev/null
}

# Truncate long detail strings so the console stays readable.
clip() {
    local text="$1" max="${2:-300}"
    if [ "${#text}" -gt "$max" ]; then
        printf '%s...' "${text:0:$max}"
    else
        printf '%s' "$text"
    fi
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Read-only scanner for the Virtualizor supply-chain compromise delivered through
the BGP hijack of 162.55.80.0/24 (28-30 August 2026).

USAGE
    sudo ./${SCRIPT_NAME} [OPTIONS]

OPTIONS
    -j, --json FILE         Write machine-readable results to FILE.
    -r, --report FILE       Write a plain-text report to FILE.
    -e, --evidence DIR      Copy artefacts and system state into DIR for
                            forensic preservation (read-only on the host).
    -f, --full-fs-scan      Sweep the whole filesystem for indicator strings
                            instead of the high-value directories only. Slow.
        --window-start TS   Override the incident window start (default:
                            "${WINDOW_START}").
        --window-end TS     Override the incident window end (default:
                            "${WINDOW_END}").
    -q, --quiet             Suppress console output; use with --json/--report.
        --color WHEN        auto (default), always or never.
    -V, --version           Print the script version and exit.
    -h, --help              Show this help and exit.

EXIT CODES
    0   No indicator found.
    1   Suspicious findings that require manual review.
    2   Confirmed indicator of compromise found.
    3   Usage or runtime error.

The script never modifies the host and makes no outbound connections.
Advisory: ${ADVISORY_URL}
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -j|--json)         [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; OPT_JSON_FILE="$2"; shift 2 ;;
            -r|--report)       [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; OPT_REPORT_FILE="$2"; shift 2 ;;
            -e|--evidence)     [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; OPT_EVIDENCE_DIR="$2"; shift 2 ;;
            -f|--full-fs-scan) OPT_FULL_FS_SCAN=1; shift ;;
            --window-start)    [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; WINDOW_START="$2"; shift 2 ;;
            --window-end)      [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; WINDOW_END="$2"; shift 2 ;;
            -q|--quiet)        OPT_QUIET=1; shift ;;
            --color)           [ $# -ge 2 ] || { printf 'Missing value for %s\n' "$1" >&2; exit 3; }; OPT_COLOR="$2"; shift 2 ;;
            -V|--version)      printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
            -h|--help)         usage; exit 0 ;;
            *)                 printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 3 ;;
        esac
    done

    case "$OPT_COLOR" in
        auto|always|never) ;;
        *) printf 'Invalid --color value: %s\n' "$OPT_COLOR" >&2; exit 3 ;;
    esac
}

banner() {
    [ "$OPT_QUIET" -eq 1 ] && return 0
    printf '%s%s' "$C_BOLD" "$C_CYAN"
    cat <<'EOF'
===============================================================================
  Virtualizor BGP Hijack - Compromise Scanner
  Supply-chain incident of 28-30 August 2026
===============================================================================
EOF
    printf '%s' "$C_RESET"
    printf '  Version        : %s\n' "$SCRIPT_VERSION"
    printf '  Host           : %s\n' "$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
    printf '  Scan started   : %s\n' "$SCAN_STARTED"
    printf '  Incident window: %s -> %s\n' "$WINDOW_START" "$WINDOW_END"
    printf '  Mode           : read-only, no outbound network traffic\n'
}

#===============================================================================
# Checks
#===============================================================================

check_environment() {
    section "1. Environment"

    if [ "$(id -u)" -ne 0 ]; then
        say_warn "Not running as root. Many checks need root and will be incomplete."
        add_finding info "ENV-001" "Scan executed without root privileges" \
            "Re-run with sudo for complete coverage."
    else
        say_ok "Running as root."
    fi

    local os="unknown"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        os="$(. /etc/os-release 2>/dev/null && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-}")"
    fi
    say_info "Operating system: ${os}"
    say_info "Kernel: $(uname -r 2>/dev/null || echo unknown)"

    if [ -d "$VZ_ROOT" ]; then
        VIRTUALIZOR_DETECTED="true"
        say_ok "Virtualizor installation detected at ${VZ_ROOT}"
    else
        say_info "No Virtualizor installation found at ${VZ_ROOT}. Host-level checks still run."
    fi

    local candidate
    for candidate in "${VZ_ROOT}/version.txt" "${VZ_ROOT}/version"; do
        [ -r "$candidate" ] || continue
        local found
        found="$(grep -Eom1 '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' "$candidate" 2>/dev/null)"
        if [ -n "$found" ]; then
            VIRTUALIZOR_VERSION="$found"
            break
        fi
    done

    if [ "$VIRTUALIZOR_VERSION" != "unknown" ]; then
        say_info "Reported Virtualizor version: ${VIRTUALIZOR_VERSION}"
        add_finding info "ENV-002" "Reported Virtualizor version is ${VIRTUALIZOR_VERSION}" \
            "The malicious package announced itself as 3.2.9.8 but affected installs kept reporting 3.2.9.7, so the version string proves nothing. Upgrade to ${FIXED_VERSION} or later regardless."
    fi
}

check_ioc_files() {
    section "2. Known indicator files"

    local file found=0
    for file in "${IOC_FILES[@]}"; do
        if [ -e "$file" ]; then
            found=1
            add_finding critical "IOC-001" "Indicator file present: ${file}" "$(file_meta "$file")"
        fi
    done

    if [ -f "$IOC_PAYLOAD" ]; then
        local hash
        hash="$(sha256_of "$IOC_PAYLOAD")"
        if [ "$hash" = "$IOC_PAYLOAD_SHA256" ]; then
            add_finding critical "IOC-002" "Payload hash matches the known RAT" \
                "${IOC_PAYLOAD} sha256=${hash}"
        elif [ -n "$hash" ]; then
            add_finding critical "IOC-003" "Payload path present with an unrecognised hash" \
                "${IOC_PAYLOAD} sha256=${hash} (expected ${IOC_PAYLOAD_SHA256}); possibly a different build."
        fi
    fi

    if [ -d /usr/lib/jvm/.cache ]; then
        add_finding critical "IOC-004" "Hidden payload directory present: /usr/lib/jvm/.cache" \
            "$(ls -la /usr/lib/jvm/.cache 2>/dev/null | tr '\n' ' ')"
    fi

    [ "$found" -eq 0 ] && say_ok "None of the known indicator files are present."
    return 0
}

check_malicious_service() {
    section "3. Persistence service"

    if ! have systemctl; then
        say_skip "systemctl not available; skipped unit inspection."
        return 0
    fi

    local flagged=0

    local units
    units="$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null | grep -F "java-jre-update" || true)"
    if [ -n "$units" ]; then
        flagged=1
        add_finding critical "SVC-001" "Malicious systemd unit registered" "$(clip "$(printf '%s' "$units" | tr '\n' ';')")"
    fi

    local state
    state="$(systemctl is-active "$IOC_SERVICE" 2>/dev/null || true)"
    if [ "$state" = "active" ] || [ "$state" = "activating" ]; then
        flagged=1
        add_finding critical "SVC-002" "Malicious service is currently ${state}" \
            "$(clip "$(systemctl status "$IOC_SERVICE" --no-pager 2>/dev/null | tr '\n' ' ')")"
    fi

    local enabled
    enabled="$(systemctl is-enabled "$IOC_SERVICE" 2>/dev/null || true)"
    if [ "$enabled" = "enabled" ]; then
        flagged=1
        add_finding critical "SVC-003" "Malicious service is enabled at boot" "$IOC_SERVICE"
    fi

    # Any unit file written during the incident window deserves a look.
    if have find; then
        local recent
        recent="$(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f \
                    -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | head -n 50)"
        if [ -n "$recent" ]; then
            flagged=1
            add_finding warning "SVC-004" "systemd units written during the incident window" \
                "$(clip "$(printf '%s' "$recent" | tr '\n' ' ')")"
        fi
    fi

    [ "$flagged" -eq 0 ] && say_ok "No malicious or window-aligned systemd unit found."
    return 0
}

check_core_file_integrity() {
    section "4. Virtualizor core file integrity"

    if [ "$VIRTUALIZOR_DETECTED" != "true" ]; then
        say_skip "Virtualizor not installed; skipped."
        return 0
    fi

    local file
    for file in "${VZ_CORE_FILES[@]}"; do
        [ -f "$file" ] || continue

        local hits
        hits="$(grep -EnI "$IOC_REGEX" -- "$file" 2>/dev/null | head -n 10)"
        if [ -n "$hits" ]; then
            add_finding critical "VZ-001" "Indicator string inside core file ${file}" \
                "$(clip "$(printf '%s' "$hits" | tr '\n' ' ')")"
            continue
        fi

        # The injection used @exec(); flag it for manual review since some
        # legitimate Virtualizor code also shells out.
        local exec_hits
        exec_hits="$(grep -EnI '@exec\s*\(|@shell_exec\s*\(|@system\s*\(|eval\s*\(\s*base64_decode' -- "$file" 2>/dev/null | head -n 10)"
        if [ -n "$exec_hits" ]; then
            add_finding warning "VZ-002" "Suppressed command execution in ${file}" \
                "Review manually against a known-good copy: $(clip "$(printf '%s' "$exec_hits" | tr '\n' ' ')" 200)"
        fi

        say_info "$(file_meta "$file") :: ${file}"
    done

    if have find; then
        local changed
        changed="$(find "$VZ_ROOT" -type f -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | head -n 100)"
        if [ -n "$changed" ]; then
            local count
            count="$(printf '%s\n' "$changed" | wc -l | tr -d ' ')"
            add_finding warning "VZ-003" "${count} Virtualizor file(s) modified during the incident window" \
                "$(clip "$(printf '%s' "$changed" | tr '\n' ' ')")"
        else
            say_ok "No Virtualizor file was modified inside the incident window."
        fi
    fi
}

check_string_sweep() {
    section "5. Indicator string sweep"

    if ! have grep; then
        say_skip "grep not available."
        return 0
    fi

    local -a targets=()
    if [ "$OPT_FULL_FS_SCAN" -eq 1 ]; then
        say_info "Full filesystem sweep requested; this can take a long time."
        targets=("/")
    else
        local dir
        for dir in "${SWEEP_DIRS[@]}"; do
            [ -e "$dir" ] && targets+=("$dir")
        done
    fi

    [ "${#targets[@]}" -eq 0 ] && { say_skip "No sweep targets present."; return 0; }

    local hits
    hits="$(grep -rIlsE --binary-files=without-match \
              --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev \
              --exclude-dir=run --exclude-dir=.git \
              "$IOC_REGEX" "${targets[@]}" 2>/dev/null \
            | grep -Fxv "$SELF_PATH" \
            | head -n 100)"

    if [ -n "$hits" ]; then
        local path
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            local sample
            sample="$(grep -EnIm2 "$IOC_REGEX" -- "$path" 2>/dev/null | tr '\n' ' ')"
            add_finding critical "SWP-001" "Indicator string found in ${path}" "$(clip "$sample" 200)"
        done <<< "$hits"
    else
        say_ok "No indicator strings found in the scanned paths."
    fi
}

check_ssh_persistence() {
    section "6. SSH persistence"

    local -a key_files=()
    local f
    for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
        [ -f "$f" ] && key_files+=("$f")
    done

    if [ -d /home ] && have find; then
        while IFS= read -r f; do
            [ -n "$f" ] && key_files+=("$f")
        done < <(find /home -maxdepth 3 -name 'authorized_keys*' -type f 2>/dev/null)
    fi

    if [ "${#key_files[@]}" -eq 0 ]; then
        say_ok "No authorized_keys files found."
        key_files=()
    fi

    # Guarded expansion: bash < 4.4 treats "${arr[@]}" on an empty array as
    # an unbound variable when set -u is active.
    for f in ${key_files[@]+"${key_files[@]}"}; do
        if grep -Fq "$IOC_SSH_KEY_BODY" "$f" 2>/dev/null; then
            add_finding critical "SSH-001" "Attacker SSH key present in ${f}" \
                "$(clip "$(grep -Fn "$IOC_SSH_KEY_BODY" "$f" 2>/dev/null | tr '\n' ' ')" 200)"
        fi

        if have ssh-keygen; then
            local fp
            fp="$(ssh-keygen -lf "$f" 2>/dev/null | grep -F "$IOC_SSH_FINGERPRINT" || true)"
            if [ -n "$fp" ]; then
                add_finding critical "SSH-002" "Attacker SSH key fingerprint present in ${f}" "$fp"
            fi
        fi

        local key_count
        key_count="$(grep -cE '^[[:space:]]*(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || true)"
        say_info "${f}: ${key_count:-0} key(s) -- verify every entry is yours."

        if have find && [ -n "$(find "$f" -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null)" ]; then
            add_finding critical "SSH-003" "${f} was modified during the incident window" "$(file_meta "$f")"
        fi
    done

    if [ -f /etc/ssh/sshd_config ]; then
        local permit
        permit="$(grep -Ei '^\s*(PermitRootLogin|PasswordAuthentication)\b' /etc/ssh/sshd_config 2>/dev/null | tr '\n' ';')"
        [ -n "$permit" ] && say_info "sshd_config: ${permit}"
        if grep -Eqi '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
            add_finding warning "SSH-004" "SSH password authentication is enabled" \
                "The attacker logged into ${IOC_ACCOUNT} with a password. Prefer key-only authentication and restrict SSH to trusted IP addresses."
        fi
        if have find && [ -n "$(find /etc/ssh -maxdepth 1 -type f -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null)" ]; then
            add_finding warning "SSH-005" "SSH configuration changed during the incident window" \
                "$(find /etc/ssh -maxdepth 1 -type f -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | tr '\n' ' ')"
        fi
    fi
}

check_accounts() {
    section "7. Local accounts"

    if have getent && getent passwd "$IOC_ACCOUNT" >/dev/null 2>&1; then
        add_finding critical "ACC-001" "Rogue account '${IOC_ACCOUNT}' exists" \
            "$(getent passwd "$IOC_ACCOUNT" 2>/dev/null)"
    elif grep -q "^${IOC_ACCOUNT}:" /etc/passwd 2>/dev/null; then
        add_finding critical "ACC-001" "Rogue account '${IOC_ACCOUNT}' exists" \
            "$(grep "^${IOC_ACCOUNT}:" /etc/passwd 2>/dev/null)"
    else
        say_ok "Rogue account '${IOC_ACCOUNT}' not present."
    fi

    local uid0
    uid0="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
    if [ -n "${uid0// /}" ]; then
        add_finding critical "ACC-002" "Additional UID 0 account(s) present" "$uid0"
    else
        say_ok "root is the only UID 0 account."
    fi

    local shell_users
    shell_users="$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false|sync)$/ {print $1"("$3")"}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
    [ -n "${shell_users// /}" ] && say_info "Interactive accounts: ${shell_users}"

    if have find && [ -n "$(find /etc/passwd /etc/shadow /etc/group -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null)" ]; then
        add_finding warning "ACC-003" "Account database changed during the incident window" \
            "$(find /etc/passwd /etc/shadow /etc/group -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | tr '\n' ' ')"
    fi

    if [ -d /etc/sudoers.d ] && have find; then
        local sudo_new
        sudo_new="$(find /etc/sudoers.d /etc/sudoers -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | tr '\n' ' ')"
        [ -n "${sudo_new// /}" ] && add_finding warning "ACC-004" "sudo configuration changed during the incident window" "$sudo_new"
    fi
}

check_scheduled_tasks() {
    section "8. Scheduled tasks"

    local -a cron_paths=(/etc/crontab /etc/cron.d /var/spool/cron /var/spool/cron/crontabs)
    local p hits_found=0

    for p in "${cron_paths[@]}"; do
        [ -e "$p" ] || continue
        local hits
        hits="$(grep -rInsE "$IOC_REGEX" -- "$p" 2>/dev/null | head -n 10)"
        if [ -n "$hits" ]; then
            hits_found=1
            add_finding critical "CRN-001" "Indicator string in cron path ${p}" "$(clip "$(printf '%s' "$hits" | tr '\n' ' ')")"
        fi

        if have find; then
            local new
            new="$(find "$p" -type f -newermt "$WINDOW_START" ! -newermt "$WINDOW_END" 2>/dev/null | tr '\n' ' ')"
            if [ -n "${new// /}" ]; then
                hits_found=1
                add_finding warning "CRN-002" "Cron entries written during the incident window" "$new"
            fi
        fi
    done

    if have systemctl; then
        local timers
        timers="$(systemctl list-timers --all --no-legend --no-pager 2>/dev/null | grep -Fi 'java-jre' || true)"
        [ -n "$timers" ] && add_finding critical "CRN-003" "Malicious systemd timer present" "$(clip "$timers")"
    fi

    [ "$hits_found" -eq 0 ] && say_ok "No malicious or window-aligned scheduled task found."
    say_info "Review root's crontab manually: crontab -l -u root"
}

check_network() {
    section "9. Network artefacts"

    local conn_output=""
    if have ss; then
        conn_output="$(ss -tunap 2>/dev/null)"
    elif have netstat; then
        conn_output="$(netstat -tunap 2>/dev/null)"
    fi

    if [ -z "$conn_output" ]; then
        say_skip "Neither ss nor netstat available; skipped socket inspection."
    else
        local ip
        for ip in "${IOC_IPS[@]}"; do
            local match
            match="$(printf '%s\n' "$conn_output" | grep -F "$ip" || true)"
            if [ -n "$match" ]; then
                add_finding critical "NET-001" "Active connection to attacker IP ${ip}" "$(clip "$(printf '%s' "$match" | tr '\n' ' ')")"
            fi
        done

        local port2025
        port2025="$(printf '%s\n' "$conn_output" | grep -E '[:.]2025\b' || true)"
        [ -n "$port2025" ] && add_finding warning "NET-002" "Socket on port 2025 (C2 port used in this incident)" \
            "$(clip "$(printf '%s' "$port2025" | tr '\n' ' ')")"
    fi

    if [ -r /etc/hosts ]; then
        local d
        for d in "${IOC_DOMAINS[@]}"; do
            grep -Fq "$d" /etc/hosts 2>/dev/null && \
                add_finding critical "NET-003" "Attacker domain pinned in /etc/hosts" "$d"
        done
    fi

    if have iptables; then
        local rules
        rules="$(iptables-save 2>/dev/null || iptables -S 2>/dev/null)"
        local ip
        for ip in "${IOC_IPS[@]}"; do
            printf '%s\n' "$rules" | grep -Fq "$ip" && \
                add_finding critical "NET-004" "Firewall rule referencing attacker IP ${ip}" \
                    "$(clip "$(printf '%s\n' "$rules" | grep -F "$ip" | tr '\n' ' ')")"
        done
    fi

    say_ok "Network artefact inspection completed."
}

check_processes() {
    section "10. Running processes"

    local ps_out
    ps_out="$(ps -eo user,pid,ppid,etime,cmd 2>/dev/null)"
    if [ -z "$ps_out" ]; then
        say_skip "Unable to enumerate processes."
        return 0
    fi

    local suspicious
    suspicious="$(printf '%s\n' "$ps_out" | grep -E 'widdow\.jar|jre-runtime\.dat|/usr/lib/jvm/\.cache' || true)"
    if [ -n "$suspicious" ]; then
        add_finding critical "PRC-001" "Malicious payload is running" "$(clip "$(printf '%s' "$suspicious" | tr '\n' ' ')")"
    fi

    local java_root
    java_root="$(printf '%s\n' "$ps_out" | awk '$1 == "root" && /java/ && !/grep/' | head -n 10)"
    if [ -n "$java_root" ]; then
        add_finding warning "PRC-002" "Java process running as root" \
            "Confirm this is expected: $(clip "$(printf '%s' "$java_root" | tr '\n' ' ')" 200)"
    fi

    local deleted
    if [ -d /proc ]; then
        deleted="$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -F '(deleted)' | head -n 10)"
        [ -n "$deleted" ] && add_finding warning "PRC-003" "Process running from a deleted binary" \
            "$(clip "$(printf '%s' "$deleted" | tr '\n' ' ')" 200)"
    fi

    say_ok "Process inspection completed."
}

check_logs() {
    section "11. Authentication logs"

    local -a logs=()
    local f
    for f in /var/log/auth.log /var/log/secure; do
        [ -r "$f" ] && logs+=("$f")
    done

    if [ "${#logs[@]}" -eq 0 ]; then
        say_skip "No readable auth log found. Try: journalctl -u sshd --since '${WINDOW_START}'"
        return 0
    fi

    local ip
    for ip in "${IOC_IPS[@]}"; do
        local match
        match="$(grep -Fh "$ip" "${logs[@]}" 2>/dev/null | head -n 5)"
        if [ -n "$match" ]; then
            add_finding critical "LOG-001" "Authentication log references attacker IP ${ip}" \
                "$(clip "$(printf '%s' "$match" | tr '\n' ' ')")"
        fi
    done

    local acct
    acct="$(grep -Fh "$IOC_ACCOUNT" "${logs[@]}" 2>/dev/null | head -n 5)"
    [ -n "$acct" ] && add_finding critical "LOG-002" "Authentication log references '${IOC_ACCOUNT}'" \
        "$(clip "$(printf '%s' "$acct" | tr '\n' ' ')")"

    if have last; then
        local sessions
        sessions="$(last -F 2>/dev/null | grep -E "$(printf '%s|' "${IOC_IPS[@]}" | sed 's/|$//' | sed 's/\./\\./g')" | head -n 5)"
        [ -n "$sessions" ] && add_finding critical "LOG-003" "Login session from an attacker IP" \
            "$(clip "$(printf '%s' "$sessions" | tr '\n' ' ')")"
    fi

    say_ok "Log inspection completed."
}

check_hygiene_advisories() {
    section "12. Post-incident hygiene"

    add_finding info "ADV-001" "Rotate every Virtualizor API key" \
        "In the Virtualizor master panel reset all API keys, remove keys you do not recognise, and restrict API access to trusted IP addresses."
    add_finding info "ADV-002" "Regenerate Softaculous Client Center API keys" \
        "Regenerate at https://www.softaculous.com/clients and update them on all servers."
    add_finding info "ADV-003" "Reset the client-area password" \
        "Required if you signed in to softaculous.com/clients or entered payment details during the incident window, and anywhere the password was reused."
    add_finding info "ADV-004" "Upgrade Virtualizor to ${FIXED_VERSION} or later" \
        "Patch 9 adds the vendor Security Analyzer. Note that package signing was still pending at the time of the advisory."
    add_finding info "ADV-005" "Restrict SSH and the admin panel by source IP" \
        "Never expose the management interface or API to the whole internet."

    say_info "These advisories apply to every Virtualizor operator, even on a clean host."
}

#===============================================================================
# Evidence collection
#===============================================================================

collect_evidence() {
    [ -n "$OPT_EVIDENCE_DIR" ] || return 0

    section "Evidence collection"

    local stamp dest
    stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    dest="${OPT_EVIDENCE_DIR%/}/virtualizor-evidence-$(hostname -s 2>/dev/null || echo host)-${stamp}"

    if ! mkdir -p "${dest}/files" "${dest}/state" 2>/dev/null; then
        say_warn "Cannot create evidence directory ${dest}"
        return 1
    fi
    chmod 700 "${dest}" 2>/dev/null

    local file
    for file in "${IOC_FILES[@]}" "${VZ_CORE_FILES[@]}" /root/.ssh/authorized_keys /etc/passwd /etc/group; do
        [ -e "$file" ] || continue
        local flat="${file//\//_}"
        cp -a -- "$file" "${dest}/files/${flat}" 2>/dev/null && say_info "Preserved ${file}"
        [ -f "$file" ] && printf '%s  %s\n' "$(sha256_of "$file")" "$file" \
            >> "${dest}/files/SHA256SUMS.txt" 2>/dev/null
    done

    {
        printf '# Host state captured %s\n\n' "$(utc_now)"
        printf '## uname\n';            uname -a 2>/dev/null
        printf '\n## processes\n';      ps -eo user,pid,ppid,lstart,etime,cmd 2>/dev/null
        printf '\n## sockets\n';        (ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null)
        printf '\n## systemd units\n';  systemctl list-units --all --no-pager 2>/dev/null
        printf '\n## systemd timers\n'; systemctl list-timers --all --no-pager 2>/dev/null
        printf '\n## root crontab\n';   crontab -l -u root 2>/dev/null
        printf '\n## logins\n';         last -F 2>/dev/null | head -n 100
        printf '\n## firewall\n';       (iptables-save 2>/dev/null || iptables -S 2>/dev/null)
    } > "${dest}/state/system-state.txt" 2>/dev/null

    say_ok "Evidence written to ${dest}"
    say_warn "Contact ${SUPPORT_URL} before remediating. Do not delete artefacts."
    add_finding info "EVD-001" "Evidence collected" "$dest"
}

#===============================================================================
# Reporting
#===============================================================================

verdict() {
    if [ "$COUNT_CRITICAL" -gt 0 ]; then
        printf 'compromised'
    elif [ "$COUNT_WARNING" -gt 0 ]; then
        printf 'suspicious'
    else
        printf 'clean'
    fi
}

print_summary() {
    [ "$OPT_QUIET" -eq 1 ] && return 0

    local v
    v="$(verdict)"

    printf '\n%s%s' "$C_BOLD" "$C_CYAN"
    printf '===============================================================================\n'
    printf '  SUMMARY\n'
    printf '===============================================================================%s\n' "$C_RESET"
    printf '  Critical indicators : %s%d%s\n' "$([ "$COUNT_CRITICAL" -gt 0 ] && printf '%s' "$C_RED$C_BOLD")" "$COUNT_CRITICAL" "$C_RESET"
    printf '  Warnings            : %s%d%s\n' "$([ "$COUNT_WARNING" -gt 0 ] && printf '%s' "$C_YELLOW")" "$COUNT_WARNING" "$C_RESET"
    printf '  Advisories          : %d\n' "$COUNT_INFO"
    printf '  Scan finished       : %s\n\n' "$SCAN_FINISHED"

    case "$v" in
        compromised)
            printf '%s%s  VERDICT: INDICATORS OF COMPROMISE FOUND%s\n\n' "$C_BOLD" "$C_RED" "$C_RESET"
            cat <<EOF
  This host shows at least one confirmed indicator. The malicious update ran as
  root, so deleting the artefacts is not remediation.

  Do now, in this order:
    1. Isolate the host at the network level, but do NOT reboot it and do NOT
       restart Virtualizor or zzvirtservice: an infected startup script would
       execute the payload again.
    2. Preserve evidence. Re-run this script with --evidence /path if you have
       not already.
    3. Contact Virtualizor support before remediating: ${SUPPORT_URL}
    4. Rotate every credential the host could reach: Virtualizor API keys,
       Client Center API keys, SSH keys, panel and database passwords.
    5. Plan a clean rebuild. Root-level compromise cannot be reliably undone.
EOF
            ;;
        suspicious)
            printf '%s%s  VERDICT: REVIEW REQUIRED%s\n\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
            cat <<EOF
  No confirmed indicator was found, but some findings need a human decision.
  Compare the flagged files against known-good copies, confirm that every SSH
  key, account and scheduled task is yours, and complete the hygiene steps.
EOF
            ;;
        clean)
            printf '%s%s  VERDICT: NO KNOWN INDICATOR FOUND%s\n\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
            cat <<EOF
  No known indicator was detected. This is not proof that the host is clean:
  the published indicators describe one observed payload only, and the vendor
  cannot supply a definitive list of affected servers. Still complete the
  hygiene steps in section 12.
EOF
            ;;
    esac

    printf '\n  Advisory: %s\n' "$ADVISORY_URL"
}

write_report() {
    [ -n "$OPT_REPORT_FILE" ] || return 0

    {
        printf 'Virtualizor BGP Hijack - Compromise Scan Report\n'
        printf '==============================================\n\n'
        printf 'Scanner        : %s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf 'Host           : %s\n' "$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
        printf 'Scan started   : %s\n' "$SCAN_STARTED"
        printf 'Scan finished  : %s\n' "$SCAN_FINISHED"
        printf 'Incident window: %s -> %s\n' "$WINDOW_START" "$WINDOW_END"
        printf 'Virtualizor    : detected=%s version=%s\n' "$VIRTUALIZOR_DETECTED" "$VIRTUALIZOR_VERSION"
        printf 'Verdict        : %s\n' "$(verdict)"
        printf 'Counts         : critical=%d warning=%d info=%d\n\n' "$COUNT_CRITICAL" "$COUNT_WARNING" "$COUNT_INFO"
        printf 'Findings\n--------\n'

        local record severity id title detail
        for record in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
            IFS="$FS" read -r severity id title detail <<< "$record"
            printf '[%s] %s: %s\n' "$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')" "$id" "$title"
            [ -n "$detail" ] && printf '        %s\n' "$detail"
        done

        printf '\nAdvisory: %s\n' "$ADVISORY_URL"
        printf 'Support : %s\n' "$SUPPORT_URL"
    } > "$OPT_REPORT_FILE" 2>/dev/null && say_ok "Report written to ${OPT_REPORT_FILE}" \
        || say_warn "Could not write report to ${OPT_REPORT_FILE}"
}

write_json() {
    [ -n "$OPT_JSON_FILE" ] || return 0

    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$(json_escape "$SCRIPT_NAME")"
        printf '  "version": "%s",\n' "$(json_escape "$SCRIPT_VERSION")"
        printf '  "hostname": "%s",\n' "$(json_escape "$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)")"
        printf '  "scan_started_utc": "%s",\n' "$(json_escape "$SCAN_STARTED")"
        printf '  "scan_finished_utc": "%s",\n' "$(json_escape "$SCAN_FINISHED")"
        printf '  "incident_window": { "start": "%s", "end": "%s" },\n' \
            "$(json_escape "$WINDOW_START")" "$(json_escape "$WINDOW_END")"
        printf '  "virtualizor_detected": %s,\n' "$VIRTUALIZOR_DETECTED"
        printf '  "virtualizor_version": "%s",\n' "$(json_escape "$VIRTUALIZOR_VERSION")"
        printf '  "verdict": "%s",\n' "$(verdict)"
        printf '  "counts": { "critical": %d, "warning": %d, "info": %d },\n' \
            "$COUNT_CRITICAL" "$COUNT_WARNING" "$COUNT_INFO"
        printf '  "findings": [\n'

        local i=0 total="${#FINDINGS[@]}" record severity id title detail comma
        for record in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
            [ -n "$record" ] || continue
            IFS="$FS" read -r severity id title detail <<< "$record"
            i=$((i + 1))
            comma=","
            [ "$i" -eq "$total" ] && comma=""
            printf '    { "severity": "%s", "id": "%s", "title": "%s", "detail": "%s" }%s\n' \
                "$(json_escape "$severity")" "$(json_escape "$id")" \
                "$(json_escape "$title")" "$(json_escape "$detail")" "$comma"
        done

        printf '  ],\n'
        printf '  "advisory": "%s"\n' "$(json_escape "$ADVISORY_URL")"
        printf '}\n'
    } > "$OPT_JSON_FILE" 2>/dev/null && say_ok "JSON written to ${OPT_JSON_FILE}" \
        || say_warn "Could not write JSON to ${OPT_JSON_FILE}"
}

#===============================================================================
# Main
#===============================================================================

main() {
    parse_args "$@"
    setup_colors

    SCAN_STARTED="$(utc_now)"
    banner

    check_environment
    check_ioc_files
    check_malicious_service
    check_core_file_integrity
    check_string_sweep
    check_ssh_persistence
    check_accounts
    check_scheduled_tasks
    check_network
    check_processes
    check_logs
    check_hygiene_advisories
    collect_evidence

    SCAN_FINISHED="$(utc_now)"

    print_summary
    write_report
    write_json

    if [ "$COUNT_CRITICAL" -gt 0 ]; then
        exit 2
    elif [ "$COUNT_WARNING" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"
