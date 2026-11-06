# php2shell-lab

Lab research for **CVE-2026-109618 / CVE-2026-109619** — a heap use-after-free in
PHP's `session.upload_progress` handler (`php_session_rfc1867_callback`,
`ext/session/session.c`).

This repository contains:

- `poc_rce.py` — a gated PoC for CVE-2026-109618 on verified PHP/Apache builds,
  with custom command execution and output retrieval.
- `phpwn/` — a separate session-upload-progress + LFI command runner.
- `php-session-upload-progress.patch` — the upstream PHP patch for reference.
- `RESULTS.md` — lab results, verified builds, and limitations.

## Status

| Item | Status |
|---|---|
| CVE-2026-109618 RCE, `php:8.5.10-apache` aarch64 | **proven in this lab** (`uid=33(www-data)`) |
| CVE-2026-109618 RCE, other verified profiles | research profiles (8.4.26 amd64, 8.5.11 amd64/aarch64) |
| CVE-2026-109619 FPM | producer OOM proven; remote RCE not publicly available |
| PHP 8.3.x | no verified RCE profile; leak-only / structurally blocked for the stock chain |
| OpenResty/FPM targets | not supported by the mod_php chain |

The vulnerability is in PHP core, not in WordPress/Drupal/Joomla. The application
only needs to expose a PHP endpoint on a vulnerable server. A memory-corruption
exploit is build-specific: offsets, heap grooming, architecture, SAPI, and runtime
configuration all matter. A version in the affected range is necessary, not sufficient.

## Quick start (verified lab)

Requirements: Apache prefork + mod_php, one worker, `memory_limit` low enough to
OOM, `display_errors=On`, `session.upload_progress.enabled=On`.

```bash
# preflight only
python3 poc_rce.py -u http://LAB/index.php --check --arch aarch64

# run the chain, custom command, output returned
python3 poc_rce.py -u http://LAB/index.php --auto --arch aarch64 -c "id"
python3 poc_rce.py -u http://LAB/index.php --auto --arch aarch64 -c "ls -la"
```

For a self-signed HTTPS lab add `--insecure`. The command is limited to 14 bytes
by the 167-byte payload carrier; the tool appends `>p.txt` and fetches `/p.txt`
by default. Use `--fetch /path` or `--proof-file` for other output channels.

### Black-box probe

No server-side `php -i` required. The probe sends Stage-1 leak requests and
reports whether the target actually leaked worker memory:

```bash
python3 poc_rce.py -u https://TARGET/index.php \
  --probe --probe-max 6 --probe-mb 0 --path /index.php --insecure
```

Output:

```
[*] POST check: HTTP 200
[*] attempt 1/1: N=841 forge=63
    oom=200/memory cookie=4096 bytes chunk=0xe00000
LEAK_CONFIRMED
```

`LEAK_CONFIRMED` is remote behavioral evidence of the over-read. `NO_LEAK_CONFIRMED`
means the tried grooming shapes did not produce a leak; it does not by itself prove
the PHP version is fake. `oom=200` without `/memory` means the OOM was not observed
(high `memory_limit`, `display_errors=Off`, or the request did not reach PHP).

## Verified profiles

`poc_rce.py` ships profiles from public research plus the lab-proven 8.5.10 build:

| Build | Arch | Status |
|---|---|---|
| PHP 8.5.10 | aarch64 | RCE proven in this lab |
| PHP 8.5.11 | amd64/aarch64 | verified research profile |
| PHP 8.4.26 | amd64 | verified research profile |
| PHP 8.4.25 | aarch64 | leaks-only |
| PHP 8.3.x | — | no verified RCE profile |

Unknown builds need a `--profile-file` (see the JSON profile format in
`poc_rce.py`) or calibration. The tool refuses to guess when a profile is missing.

## phpwn (LFI chain)

`phpwn` is a separate command runner that uses the documented upload-progress
session-file write and a local file inclusion to execute a command:

```bash
python3 -m phpwn \
  --url https://lab.local/index.php \
  --lfi "https://lab.local/lfi.php?file=" \
  --sessions /var/lib/php/sessions \
  --cmd "id"
```

This requires an LFI and `session.upload_progress.cleanup=Off` (or a successful
slow-upload race). It is not the CVE-2026-109618 memory-corruption chain.

## Results

See [`RESULTS.md`](RESULTS.md) for the exact lab image, `libphp.so` hash, commands,
outputs, and the 109619 FPM findings.

## References

- [NVD CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
- [NVD CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- [Wiz Research — php2shell](https://www.wiz.io/blog/php2shell-php-rce)
- [PHP session.upload_progress documentation](https://www.php.net/manual/en/session.upload-progress.php)

## Authorization

Run only against labs you own or have explicit permission to test. The PoC sends
OOM bodies, rotates/crashes workers, and executes commands on the target.
