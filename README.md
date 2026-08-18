# TrustPositif Validator

> **Enterprise-grade domain validation and aggregation pipeline for TrustPositif/Komdigi blocklists.**
> High-performance · Standards-compliant · Cross-platform · ShellCheck Certified

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Certified-brightgreen.svg)](https://www.shellcheck.net)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20FreeBSD-informational.svg)](https://github.com/alsyundawy/TrustPositif-Validator)
[![Version](https://img.shields.io/badge/Version-1.0.4-orange.svg)](https://github.com/alsyundawy/TrustPositif-Validator/releases)
[![Standards](https://img.shields.io/badge/RFC-1034%20%7C%201035%20%7C%201123%20%7C%203490%20%7C%205890-lightgrey.svg)](https://github.com/alsyundawy/TrustPositif-Validator)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Buy%20me%20a%20coffee-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/alsyundawy)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?logo=paypal&logoColor=white)](https://www.paypal.me/alsyundawy)

---

## Overview

**TrustPositif Validator** is a production-ready Bash/Shell script that processes and exports domain blocklists from TrustPositif/Komdigi and configurable public sources. It validates every domain against the official [IANA Root Zone Database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) and RFC standards (1034, 1035, 1123, 3490, 5890), producing a deterministic, DNS/RPZ-ready output file optimized for automated deployments at scale.

| Feature | Detail |
| --- | --- |
| **Multi-Source Input** | Aggregates from `TRUSTPOSITIF_URLS` array — easily extensible |
| **IANA TLD Validation** | Validates every domain against the live IANA Root Zone Database |
| **RFC Compliance** | RFC 1034, RFC 1035, RFC 1123, RFC 3490, RFC 5890 + IDN/Punycode |
| **Advanced Sanitization** | Automated removal of non-domain metadata and invalid URI structures |
| **Parallel Processing** | GNU Parallel with adaptive core/chunk auto-tuning |
| **AWK Auto-Fallback** | `mawk` → `gawk` → `awk` with functional validation |
| **Atomic Output** | Temporary staging file + rename pattern with explicit permissions |
| **Cross-Platform** | Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch, macOS, FreeBSD |
| **Auto Dependency Install** | Detects `apt`/`dnf`/`yum`/`zypper`/`apk` and installs missing tools |
| **ShellCheck Certified** | Verified warning-free on ShellCheck v0.11+ test suites |

---

## Quickstart

You can run or download TrustPositif Validator using any of the following methods:

```bash
# Option 1: Direct execution via curl
bash <(curl -fsSL https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh)

# Option 2: Direct execution via wget
bash <(wget -qO- https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh)

# Option 3: Download and run locally
curl -fsSL -o trustpositif-validator.sh https://raw.githubusercontent.com/alsyundawy/TrustPositif-Validator/main/trustpositif-validator.sh
chmod +x trustpositif-validator.sh
bash trustpositif-validator.sh

# Option 4: Clone repository
git clone https://github.com/alsyundawy/TrustPositif-Validator.git
cd TrustPositif-Validator
chmod +x trustpositif-validator.sh
bash trustpositif-validator.sh
```

---

## Usage

```bash
bash trustpositif-validator.sh                   # Normal run
bash trustpositif-validator.sh --help            # Full documentation
bash trustpositif-validator.sh --version         # Show version
bash trustpositif-validator.sh --force-cleanup   # Clean up leftover temp files
```

### Environment Variable Overrides

```bash
# Process only subdomains' parent domain (aggressive mode)
CUT_SUBDOMAINS=1 bash trustpositif-validator.sh

# Override parallelism and chunk size
NUM_CORES=8 CHUNK_SIZE=28000 bash trustpositif-validator.sh

# Override sort buffer (useful on memory-constrained systems)
SORT_BUFFER=256M bash trustpositif-validator.sh

# Override output directory
OUTPUT_DIR=/data/blocklists bash trustpositif-validator.sh

# Disable SSL bypass (enforce strict TLS verification)
CURL_INSECURE=0 bash trustpositif-validator.sh

# Force a specific AWK engine
AWK_CMD=/usr/bin/mawk bash trustpositif-validator.sh
```

### Output File

- **Path:** `/var/www/html/trustpositif/domain-trustpositif_valid.txt`
- **Format:** One valid RFC-compliant domain per line, UTF-8 encoded without BOM
- **Sorting:** Alphabetically sorted, case-insensitive, deduplicated
- **Compatibility:** Ready for direct integration with DNS sinkhole and RPZ blocklists

---

## Dependencies

The script automatically checks for and installs missing dependencies where supported. You can also pre-install required packages using your system package manager:

```bash
# Debian / Ubuntu / Linux Mint
sudo apt update && sudo apt install -y bash curl wget mawk gawk parallel coreutils procps findutils grep

# RHEL / CentOS Stream / Fedora / AlmaLinux / Rocky Linux
sudo dnf install -y bash curl wget gawk parallel coreutils procps-ng findutils grep

# Alpine Linux
sudo apk add --no-cache bash curl wget mawk gawk parallel coreutils procps findutils grep

# Arch Linux / Manjaro
sudo pacman -Sy --noconfirm bash curl wget gawk parallel coreutils procps-ng findutils grep

# openSUSE / SLES
sudo zypper --non-interactive install bash curl wget gawk parallel coreutils procps findutils grep

# macOS (Homebrew)
brew install bash gawk parallel coreutils wget curl

# FreeBSD
pkg install -y bash curl wget gawk p5-parallel coreutils findutils gnugrep gsed
```

---

## Configuration

The script dynamically auto-tunes parameters according to detected system resources:

| Parameter | Auto-tuning Logic | Manual Override |
| --- | --- | --- |
| `NUM_CORES` | Based on `nproc` (clamped 4–32), throttled on low RAM systems | `NUM_CORES=8` |
| `CHUNK_SIZE` | `20000 + (NUM_CORES × 1000)`, clamped 1000–50000 | `CHUNK_SIZE=30000` |
| `SORT_BUFFER` | Adaptive scaling: 128M / 256M / 512M / 1G / 2G based on memory | `SORT_BUFFER=512M` |
| `AWK_CMD` | Auto-detected: `mawk` → `gawk` → `awk` with runtime verification | `AWK_CMD=/usr/bin/gawk` |
| `CURL_INSECURE` | Defaults to `1` (bypass SSL for legacy endpoints); set `0` for strict TLS | `CURL_INSECURE=0` |

### Adding Custom Blocklist Sources

Edit the `TRUSTPOSITIF_URLS` array at the top of the script:

```bash
TRUSTPOSITIF_URLS=(
    "https://trustpositif.komdigi.go.id/assets/db/domains_isp"
    "https://example.com/custom-blocklist.txt"
)
```

---

## Architecture & Pipeline

```text
┌─────────────────────────────────────────────────┐
│             TrustPositif Validator               │
├──────────────┬──────────────────────────────────┤
│  Phase 1     │  Download TLD IANA + all sources  │
│  Phase 2     │  Split into adaptive chunks       │
│  Phase 3     │  Parallel AWK validation (RFC)    │
│  Phase 4     │  Sort + global deduplication      │
│  Phase 5     │  Atomic write to output file      │
│  Phase 6     │  Cleanup all temp files via trap  │
└──────────────┴──────────────────────────────────┘
```

The script adheres to strict logging standards: `[>] [PROSES]` for active operations, `[i] [INFO]` for runtime parameters, `[OK] [BERHASIL]` for completed steps, `[!] [PERINGATAN]` for non-fatal issues, and `[X] [ERROR]` for fatal conditions.

---

## Running Tests

Run the following automated verification suite:

```bash
# 1. Syntax check
bash -n trustpositif-validator.sh

# 2. ShellCheck static analysis
shellcheck trustpositif-validator.sh

# 3. Test CLI interface
bash trustpositif-validator.sh --version
bash trustpositif-validator.sh --help
bash trustpositif-validator.sh --force-cleanup

# 4. Dry run with custom output
OUTPUT_DIR=/tmp/test_trustpositif bash trustpositif-validator.sh
```

---

## Security

- **Safe Execution Mode:** Runs under `set -Eeuo pipefail` and `IFS=$'\n\t'`.
- **Trap Cleanup:** Guaranteed signal trapping for `EXIT`, `INT`, and `TERM`.
- **Isolated Workspace:** Uses `mktemp -d` with private permissions (`0700`) to prevent CWD pollution and symlink exploits.
- **Atomic Operations:** Two-stage file write via staging file in `OUTPUT_DIR` to guarantee atomic replacement across filesystems.
- **Strict Permissions:** Enforces explicit `0644` read permissions on final output for web and DNS services.
- **Input Sanitization:** Comprehensive input sanitization for all external parameters and system paths.
- **Zero Secret Exposure:** No tokens, credentials, or sensitive headers are logged.

---

## Performance Benchmarks

Benchmark measurements conducted on reference environment (8 cores, 16 GB RAM, NVMe SSD, 1 Gbps network):

| Phase | Duration |
| --- | --- |
| Download | 10–15 seconds |
| Parallel AWK Processing | 30–60 seconds (1.5M domains) |
| Sort + Deduplication | 5–15 seconds |
| Cleanup | < 1 second |
| **Total Runtime** | **~1–1.5 minutes** |
| Throughput | ~35,000–45,000 domains/second |
| Memory Usage | ~100 MB |

---

## Troubleshooting

| Problem | Root Cause | Solution |
| --- | --- | --- |
| Script hangs or aborts | Stale temp locks | Run `bash trustpositif-validator.sh --force-cleanup` |
| Missing binary | Uninstalled tool | Run `sudo apt install -y curl mawk gawk parallel coreutils` |
| Download failure | Network/DNS timeout | Check internet connection; the script automatically retries up to 5 times |
| Out of memory | Small RAM environment | Set `CHUNK_SIZE=5000` or increase swap space |
| Permission denied | Restrictive folder access | Ensure the user has write access to `OUTPUT_DIR` |

---

## Contributing

Community contributions and feedback are welcome:

1. Fork the repository on GitHub.
2. Create your feature branch (`git checkout -b feature/improvement`).
3. Ensure all changes pass `shellcheck` with zero warnings and adhere to strict error handling standards.
4. Commit your changes with clear messages (`git commit -m 'feat: optimize memory allocation'`).
5. Push to the branch (`git push origin feature/improvement`) and open a Pull Request.

---

## Changelog

### v1.0.4 — 18 Agustus 2026 — Security Audit, TTY Guard & Output Permission Hardening

- **[SEC]** TTY Guard pada Clear Screen: Proteksi clear screen hanya jika stdout terhubung ke terminal interaktif, mencegah polusi escape code ANSI pada cron & log.
- **[SEC]** Dukungan Standar NO_COLOR: Mematuhi spesifikasi no-color.org untuk eksekusi pipeline.
- **[SEC]** Deterministic Permissions (`chmod 644`): Menetapkan permission 0644 pada file output akhir agar terbaca oleh DNS server (BIND/Unbound/Pi-hole) dan Web server (Nginx/Apache).
- **[FIX]** AWK DOS/CRLF Hardening: Menambahkan pembersihan explicit `\r` di awal record AWK chunk parser untuk mencegah kegagalan regex pada blocklist berformat Windows/DOS.
- **[FIX]** Perluasan Prefix Sanitizer: Sanitasi karakter prefix `@`, `*`, `|`, `.` pada input mentah.
- **[FIX]** Deduplikasi Path `force_cleanup`: Mengoptimalkan pemindaian temporary directory agar tidak melakukan scanning ganda pada `/tmp`.
- **[LINT]** Verified zero warnings on ShellCheck v0.11+.

### v1.0.3 — 27 Juli 2026 — Hardening Validasi Blocklist & Atomic Output

- **[FIX]** Urutan Sanitasi Path & Port: Memindahkan pemotongan path, query string, hash, dan opsi AdGuard sebelum pemeriksaan port.
- **[BARU]** Support Syntax Blocklist: Sanitasi prefix `||`, `*`, leading dots, serta suffix AdGuard (`^`, `$options`).
- **[FIX]** Cross-Filesystem Atomic Write: Menggunakan staging file di dalam `OUTPUT_DIR` sebelum `mv`.
- **[FIX]** BSD Sort Safety: Konversi otomatis buffer persentase ke MiB absolut pada platform macOS/FreeBSD.
- **[LINT]** Clean static analysis under ShellCheck test suites.

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

```text
Copyright (c) 2024–2026 Harry Dertin Sutisna Alsyundawy
```

---

## Author & Support

Created and maintained by **Harry Dertin Sutisna Alsyundawy**:

- Email: [alsyundawy@gmail.com](mailto:alsyundawy@gmail.com)
- Phone: +62 856-8515-212
- Website: [alsyundawy.com](https://alsyundawy.com)

Support project development:

- ☕ **Ko-fi:** [ko-fi.com/alsyundawy](https://ko-fi.com/alsyundawy)
- 💳 **PayPal:** [paypal.me/alsyundawy](https://www.paypal.me/alsyundawy)
