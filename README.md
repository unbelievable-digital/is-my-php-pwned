# is-my-php-pwned 🔥

**Did php2shell already own your servers? Run one read-only script and find out.**

On **21 October 2026** the PHP project disclosed two critical, unauthenticated
remote-code-execution bugs — **CVE-2026-109618** and **CVE-2026-109619**,
collectively nicknamed **php2shell** (CVSS 9.2 each). Proof-of-concept code
leaked *before* the patches shipped, so the window between "exploit public" and
"you patched" was wide open for a lot of servers.

This repo is the script we wrote to sweep our own fleet and answer two
questions fast:

1. **Am I still vulnerable?** (which PHP version is actually running)
2. **Was I already hit?** (post-exploitation indicators of compromise)

It is **100% read-only**. It never writes, deletes, restarts, or "fixes"
anything. It does **not** contain or run any exploit. It just looks and reports.

---

## The bugs, briefly

| CVE | Nickname | What it is | Worst case |
|-----|----------|------------|------------|
| CVE-2026-109618 | OOM corruption | Hitting `memory_limit` at the wrong moment leaves half-initialized memory that PHP later trusts | **Unauthenticated RCE before app code runs** on Apache + mod_php (default config) |
| CVE-2026-109619 | Stale global state | A fatal error leaves internal state pointing at freed request memory; the next request on the same worker uses it | Use-after-free → worker crash → RCE, demonstrated on mod_php |

**Fixed in:** PHP **8.5.12**, **8.4.27**, **8.3.36**, **8.2.35**.
**No fix:** PHP 8.1 and older are end-of-life — upgrade, there is no patch.

**There is no config workaround.** Disabling `session.upload_progress`,
tweaking `memory_limit` or `post_max_size` only narrows exposure; the PHP
security team was explicit that "ini settings won't save you." **Patching is
the only fix.** This script tells you where you stand — it is not a substitute
for updating PHP.

`mod_php` is the dangerous SAPI (pre-auth, pre-app). `php-fpm` is exploitable
too, but through application code paths, so it is more conditional. The script
reports every PHP runtime it finds either way.

---

## Usage

```bash
# scan the local host, default 7-day lookback for file/log indicators
sudo bash php2shell-ioc-scan.sh

# widen the lookback, point at an explicit web root
sudo bash php2shell-ioc-scan.sh --days 30 --webroot /var/www

# over SSH, no copy needed
ssh root@host 'bash -s -- --days 14' < php2shell-ioc-scan.sh
```

Exit codes: `0` nothing flagged · `1` indicators to review · `2` bad arguments.

### Fleet sweep

```bash
for h in web1 web2 web3; do
  echo "===== $h"
  ssh "root@$h" 'bash -s -- --days 14' < php2shell-ioc-scan.sh
done
```

---

## What it checks

1. **PHP version vs fixed** — every `php-fpm*`, LiteSpeed `lsphp*` and
   `frankenphp` binary on the box, flagged `VULNERABLE`, `EOL`, or `OK`.
2. **Recently-changed PHP** in web roots (default: last 7 days) — fresh files
   are where a dropped webshell shows up first.
3. **Webshell signatures**, two tiers: loud, high-confidence markers
   (`c99shell`, `eval($_POST…)`, `gzinflate(base64_decode($…))`, dynamic
   superglobal calls…) always; generic packer markers only when the file also
   changed recently — this keeps vendored libraries (PHPMailer, WordPress core,
   Composer trees) from drowning you in false positives.
4. **PHP-FPM / FrankenPHP segfault & OOM footprints** in logs and journal —
   php2shell leans on OOM and use-after-free, so a spike of worker crashes is
   worth a look.
5. **World-writable PHP** in web roots.
6. **Suspicious processes** — reverse shells, miners, `curl … | sh`.
7. **Listeners owned by the web user.**
8. **Persistence** — `cron` entries and `authorized_keys` changed in the window.

Every finding is a *lead to triage*, not a verdict. A clean run is **not** proof
you are safe — it means nothing obvious was found. Patch anyway.

---

## Limitations

- Signature scanning is heuristic. It will miss a well-hidden shell and it will
  occasionally flag legitimate code (looking at you, RevSlider). Read each hit.
- It inspects the host it runs on. Containers, chroots and remote storage need
  their own pass.
- It assumes a Linux host with `bash`, `find`, `grep`; `ss`/`journalctl`
  improve coverage when present.

## Contributing

PRs welcome — especially additional high-confidence signatures with low false
positive rates, and support for more SAPIs. Keep it read-only. Never add
anything that writes to or exploits a target.

## License

MIT — see [LICENSE](LICENSE). Use freely, no warranty.
