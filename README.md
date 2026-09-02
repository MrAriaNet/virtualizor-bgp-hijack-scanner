# Virtualizor BGP Hijack — Compromise Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash%204.2%2B-121011?logo=gnubash&logoColor=white)](#requirements)
[![Mode](https://img.shields.io/badge/mode-read--only-brightgreen.svg)](#safety-guarantees)
[![Network](https://img.shields.io/badge/network-offline-informational.svg)](#safety-guarantees)

A read-only triage scanner for the Virtualizor supply-chain compromise that was delivered through the BGP hijack of `162.55.80.0/24` between **28 August 2026, 20:57 UTC** and **30 August 2026, 06:10 UTC**.

The script checks a host against every publicly documented indicator of compromise, explains what it found, and tells you what to do next. It never deletes, disables or "cleans" anything, because the vendor asks operators to preserve evidence and contact support before remediating an affected server.

---

## Table of contents

- [Background](#background)
- [Am I affected?](#am-i-affected)
- [Quick start](#quick-start)
- [What the scanner checks](#what-the-scanner-checks)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Sample output](#sample-output)
- [If indicators are found](#if-indicators-are-found)
- [If nothing is found](#if-nothing-is-found)
- [Indicators of compromise](#indicators-of-compromise)
- [Safety guarantees](#safety-guarantees)
- [Requirements](#requirements)
- [Known limitations](#known-limitations)
- [Verifying the official vendor script](#verifying-the-official-vendor-script)
- [References](#references)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Background

Traffic on the internet is routed with BGP, a protocol that has historically relied on networks trusting each other's route announcements. On 28 August 2026 at approximately 20:57 UTC, AS62390 (NexonHost) began announcing `162.55.80.0/24` — a slice of Hetzner address space hosting Softaculous infrastructure — without authorization, via transit provider AS6204 (Zet.net).

Because that announcement was more specific than Hetzner's legitimate `162.55.0.0/16`, it won BGP route selection on every network that received it. At peak, roughly 72% of RIPE RIS collector peers had a best path through the hijacker. The route flapped heavily and ran in two waves, separated by an eleven-hour lull.

The attacker also obtained a technically valid Let's Encrypt certificate for the affected domains, because the certificate authority's domain-ownership validation was routed through the hijack as well. Clients therefore saw **no TLS warning**.

Virtualizor's update client did not cryptographically verify update packages at the time. Any installation whose update check landed inside a diverted interval could receive a malicious package that announced itself as version `3.2.9.8`.

**What the malicious package did**, according to forensic reports from affected hosting providers:

1. Injected `@exec()` calls into three legitimate Virtualizor files: `globals.php`, `_universal.php` and the `zzvirtservice` startup script.
2. Waited for Virtualizor's own root cron job (`virt_check.php`) to execute the injected code.
3. Wrote an attacker-controlled SSH key into `/root/.ssh/authorized_keys`.
4. Installed Java 17 if it was missing, downloaded `widdow.jar` from `cdn.nerat.cc`, and ran it as root.
5. Registered the systemd unit `java-jre-update.service` for persistence and beaconed to `31.77.220.138:2025`.
6. On at least one host, created a `proxyuser` account, opened a firewall rule, and held an interactive SSH session for over three hours.

One provider found the same modifications on 5 of its 34 hypervisor nodes. The vendor cannot produce a definitive list of affected servers, because the malicious responses came from the attacker's system and never reached Softaculous logs.

> **The reported version number proves nothing.** Affected installations continued to report `3.2.9.7` after the malicious `3.2.9.8` package was applied. Check the files, not the version string.

## Am I affected?

There is no affected-version range. The vendor's guidance is that **every Virtualizor operator should check every server**. Run the scanner if any of the following is true:

- You run Virtualizor on any node, whether or not you remember an update happening.
- A server performed an update check between 28 Aug 2026 20:57 UTC and 30 Aug 2026 06:10 UTC.
- You run Webuzo, Softaculous, Backuply or SitePad and want to rule out host-level persistence. No malicious package has been identified for those products, but the host-level checks still apply.
- You signed in to `softaculous.com/clients` during the window. In that case also reset your client-area password; see [If nothing is found](#if-nothing-is-found).

## Quick start

```bash
# Download
curl -fsSLO https://raw.githubusercontent.com/MrAriaNet/virtualizor-bgp-hijack-scanner/main/virtualizor-bgp-hijack-scan.sh
chmod +x virtualizor-bgp-hijack-scan.sh

# Read it before you run it as root. It is a plain, dependency-free Bash script.
less virtualizor-bgp-hijack-scan.sh

# Scan
sudo ./virtualizor-bgp-hijack-scan.sh
```

Scan and keep the results:

```bash
sudo ./virtualizor-bgp-hijack-scan.sh \
    --report /root/vz-scan.txt \
    --json   /root/vz-scan.json
```

Scan and preserve forensic artefacts in one pass:

```bash
sudo ./virtualizor-bgp-hijack-scan.sh --evidence /root/incident
```

Scan a fleet from a management host:

```bash
for host in node01 node02 node03; do
    echo "=== $host ==="
    ssh "root@$host" 'bash -s -- --quiet --json /root/vz-scan.json' \
        < virtualizor-bgp-hijack-scan.sh
    echo "exit=$?"
done
```

An exit code of `2` from any node means that node needs immediate attention.

## What the scanner checks

| # | Section | Detections |
|---|---------|-----------|
| 1 | Environment | Root privileges, distribution, Virtualizor presence and reported version |
| 2 | Indicator files | The five known artefact paths, payload SHA-256, hidden `/usr/lib/jvm/.cache` directory |
| 3 | Persistence service | `java-jre-update.service` registered, enabled or active; any systemd unit written inside the incident window |
| 4 | Core file integrity | Indicator strings in `globals.php`, `_universal.php`, `zzvirtservice`; suppressed `@exec()` calls; Virtualizor files modified inside the window |
| 5 | String sweep | Attacker domains, payload names and IP addresses across high-value directories, or the whole filesystem with `--full-fs-scan` |
| 6 | SSH persistence | Attacker public key and key fingerprint in every `authorized_keys`, files modified in the window, password authentication enabled, `sshd_config` changes |
| 7 | Local accounts | The `proxyuser` account, extra UID 0 accounts, account database and sudo changes inside the window |
| 8 | Scheduled tasks | Indicator strings in cron paths, cron entries written in the window, malicious systemd timers |
| 9 | Network artefacts | Live sockets to attacker IPs, sockets on C2 port 2025, attacker domains pinned in `/etc/hosts`, firewall rules referencing attacker IPs |
| 10 | Processes | The running payload, root-owned Java processes, processes executing from deleted binaries |
| 11 | Authentication logs | Attacker source IPs and `proxyuser` in `auth.log` / `secure` and in the login history |
| 12 | Hygiene advisories | Credential rotation and hardening steps that apply to every operator, clean or not |

Findings are graded **critical** (a documented indicator), **warning** (needs a human decision) or **info** (advisory).

## Usage

```
sudo ./virtualizor-bgp-hijack-scan.sh [OPTIONS]

  -j, --json FILE         Write machine-readable results to FILE.
  -r, --report FILE       Write a plain-text report to FILE.
  -e, --evidence DIR      Copy artefacts and system state into DIR for forensic
                          preservation. Reads from the host only.
  -f, --full-fs-scan      Sweep the whole filesystem for indicator strings
                          instead of the high-value directories only. Slow.
      --window-start TS   Override the incident window start.
      --window-end TS     Override the incident window end.
  -q, --quiet             Suppress console output; use with --json / --report.
      --color WHEN        auto (default), always or never.
  -V, --version           Print the script version and exit.
  -h, --help              Show help and exit.
```

The window options accept any timestamp GNU `find -newermt` understands, for example `--window-start "2026-08-28 20:57:00 UTC"`. Widen the window if you want to review a longer period of change on the host.

## Exit codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | No known indicator found | Complete the hygiene checklist |
| `1` | Suspicious findings that need manual review | Investigate the flagged items |
| `2` | Confirmed indicator of compromise | Isolate, preserve evidence, contact support |
| `3` | Usage or runtime error | Fix the invocation |

This makes the scanner easy to wire into configuration management or monitoring: treat `2` as a page, `1` as a ticket.

## Sample output

```
===============================================================================
  Virtualizor BGP Hijack - Compromise Scanner
  Supply-chain incident of 28-30 August 2026
===============================================================================
  Version        : 1.0.0
  Host           : node07.example.net
  Scan started   : 2026-09-03T08:14:22Z
  Incident window: 2026-08-28 20:57:00 UTC -> 2026-08-30 06:10:00 UTC
  Mode           : read-only, no outbound network traffic

>> 1. Environment
   [ OK ] Running as root.
   [INFO] Operating system: AlmaLinux 9.4
   [ OK ] Virtualizor installation detected at /usr/local/virtualizor

>> 2. Known indicator files
   [CRIT] Indicator file present: /etc/systemd/system/java-jre-update.service
   [CRIT] Payload hash matches the known RAT
   [CRIT] Hidden payload directory present: /usr/lib/jvm/.cache

>> 3. Persistence service
   [CRIT] Malicious service is currently active

>> 6. SSH persistence
   [CRIT] Attacker SSH key present in /root/.ssh/authorized_keys

===============================================================================
  SUMMARY
===============================================================================
  Critical indicators : 5
  Warnings            : 2
  Advisories          : 5

  VERDICT: INDICATORS OF COMPROMISE FOUND
```

## If indicators are found

The malicious code ran as root. Deleting the artefacts is **not** remediation, and the vendor explicitly asks operators not to simply delete the service unit.

1. **Isolate the host at the network level.** Do not reboot it, and do not restart Virtualizor or `zzvirtservice` — an infected startup script would execute the payload again.
2. **Preserve evidence** before touching anything: `sudo ./virtualizor-bgp-hijack-scan.sh --evidence /root/incident`.
3. **Contact Virtualizor support** at <https://softaculous.deskuss.com> before remediating, so they can help preserve and interpret evidence.
4. **Rotate every credential the host could reach**: Virtualizor API keys, Softaculous Client Center API keys, SSH keys, panel passwords, database passwords, and anything stored in configuration on that node.
5. **Plan a clean rebuild.** Root-level compromise with an interactive attacker session cannot be reliably undone in place. Restore guest workloads onto a freshly built host.

## If nothing is found

A clean result means no *known* indicator was detected. The published indicators describe one observed payload, and the vendor cannot supply a definitive victim list, so absence of these artefacts is not proof of integrity. Complete the hygiene steps regardless:

- [ ] Upgrade Virtualizor to **3.2.9.9 / Patch 9** or later, which ships the vendor Security Analyzer.
- [ ] Reset **all** Virtualizor API keys in the master panel and delete any key you do not recognise.
- [ ] Restrict Virtualizor API access to trusted source IP addresses.
- [ ] Regenerate Softaculous Client Center API keys at <https://www.softaculous.com/clients> and update them on every server.
- [ ] Reset your `softaculous.com/clients` password if you signed in or entered payment details during the incident window, and change it anywhere it was reused.
- [ ] Review card statements if payment details were entered during the window.
- [ ] Restrict SSH to trusted IP addresses and prefer key-only authentication.
- [ ] Never expose the Virtualizor admin panel or API to the whole internet.
- [ ] Re-run this scanner after any Virtualizor update until package signing ships.

## Indicators of compromise

| Type | Indicator |
|------|-----------|
| Systemd unit | `/etc/systemd/system/java-jre-update.service` |
| Payload | `/usr/lib/jvm/.cache/jre-runtime.dat` (~13.5 MB) |
| Payload SHA-256 | `b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7` |
| Marker file | `/usr/lib/jvm/.cache/.installed` |
| Marker file | `/tmp/.vz_svc_done` |
| Dropped archive | `/tmp/widdow.jar` |
| Download URL | `hxxps://cdn[.]nerat[.]cc/installer/widdow.jar` |
| C2 domain | `connect[.]ne-rat[.]xyz` |
| C2 endpoint | `31.77.220[.]138:2025` |
| Attacker SSH key | `AAAAC3NzaC1lZDI1NTE5AAAAIP13pPAm5jmInLQYD3XNb3HwrW4cAKDcphoT4kSKrnte` |
| SSH key fingerprint | `SHA256:YQmy1hKF1h5cdJLxlZ5EScNoxe/UDWahjsWuQw2ERi8` |
| Rogue account | `proxyuser`, logged in from `193.32.127[.]248` |
| Modified core files | `globals.php`, `_universal.php`, `zzvirtservice` |

Hijack routing detail: prefix `162.55.80.0/24`, origin AS24940 (Hetzner, kept on the path tail), next hop AS62390 (NexonHost), transit AS6204 (Zet.net). First unauthorized announcement at `2026-08-28T20:57:30Z`, example AS path `20912 6204 62390 24940`.

Manual spot check, if you would rather not run a script:

```bash
grep -RsnE 'cdn\.nerat\.cc|widdow\.jar|jre-runtime\.dat' \
    /usr/local/virtualizor /etc/systemd/system /root/.ssh 2>/dev/null
systemctl status java-jre-update.service --no-pager
getent passwd proxyuser
```

## Safety guarantees

This scanner is deliberately conservative:

- **Read-only.** It never deletes, moves, kills, disables or modifies anything on the host. The only writes are the report, JSON and evidence files you explicitly ask for.
- **Offline.** It makes no outbound network connections, resolves no attacker domains and downloads nothing. Safe to run on an isolated host.
- **No dependencies.** Pure Bash plus standard coreutils. No package installation, no interpreter beyond `bash`.
- **Auditable.** Roughly a thousand lines of commented Bash with every indicator declared in one block at the top of the file. Read it before running it as root.

Deliberate non-goal: automated cleanup. Removing indicators would destroy evidence and give false reassurance on a host that had root-level compromise.

## Requirements

- Bash 4.2 or newer (CentOS 7 and later, Debian 8 and later, and every current distribution).
- Standard GNU userland: `grep`, `find`, `awk`, `sed`, `ps`, `stat`.
- Root privileges for full coverage. It runs unprivileged, but skips anything it cannot read and says so.
- Optional and used when present: `systemctl`, `ss` or `netstat`, `ssh-keygen`, `iptables`, `last`, `sha256sum`.

Tested against the layout of Virtualizor installations on RHEL-family and Debian-family systems.

## Known limitations

- Detection covers **published** indicators only. A different payload build, or a second-stage implant that was never documented, will not be caught. Treat a clean result as one data point, not as a clearance.
- Timestamp-based checks rely on file mtimes, which an attacker with root can forge.
- `--full-fs-scan` reads a large amount of data and can take a long time on hosts with many guest images. The default sweep covers the directories that matter.
- This repository contains indicator strings in plain text. If you clone it into a swept directory such as `/root`, the scanner will flag its own README. The script excludes itself, but not the other files. Clone it outside the swept paths, or expect and disregard that finding. Report and JSON output files have the same property.

## Verifying the official vendor script

Virtualizor also publishes its own cleaning script. Because this incident was a supply-chain attack on the vendor's own distribution path, verify what you download before running it as root:

```bash
curl -fsSLO https://files.virtualizor.com/security/virtualizor_security_scan.sh
sha256sum virtualizor_security_scan.sh
```

A third-party check on 2 September 2026 reported the SHA-256 of the retrieved script as `73e74402b3a61c7bab289fc11347bd54c7fcdc2fa2e410f4c3de9d6cd7377d48`. That value is a point-in-time observation, not a vendor-published signature, so a mismatch may simply mean the script was updated. Read any script before executing it with root privileges.

## References

- [Virtualizor — Security Incident: BGP Hijacking (official advisory)](https://www.virtualizor.com/blog/security-incident-bgp-hijacking/)
- [The Hacker News — BGP Hijack Delivers Malicious Virtualizor Update That Establishes Persistent Root Access](https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html)
- [Cyber Kendra — Virtualizor Compromised via BGP Hijack](https://www.cyberkendra.com/2026/08/virtualizor-compromised-via-bgp-hijack.html)
- [RIPE BGPlay — 162.55.80.0/24](https://stat.ripe.net/bgplay/162.55.80.0%2F24)
- Virtualizor support: <https://softaculous.deskuss.com>

## Disclaimer

This is an independent, community-maintained tool. It is not affiliated with, endorsed by, or supported by Softaculous Ltd. or Virtualizor.

It is provided as a triage aid. A clean result does not certify that a host is uncompromised, and no automated check can substitute for professional incident response on a host with confirmed root-level compromise. Use at your own risk.

## License

[MIT](LICENSE)
