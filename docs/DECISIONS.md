# Decisions

Each decision with its status, the evidence and the alternatives considered.

## D0. Name: vms-steward

**Status:** approved by the user (2026-10-10).

Repository `vms-steward`, rooted logical `STEWARD$ROOT`, image `[BIN]STEWARD.EXE`, pool
procedure `STEWARD_POOL.COM`, PCSI producer ISSINOHO. The product covers the same ground
as VSI's commercial WebUI, so the name must not resemble it: "webui" and "webadmin" were
rejected for that reason, along with "bosun" and "warden" (the latter undersells the
monitoring areas to come). C identifiers use the prefix `st_`, and HTTP headers use
`X-Steward-`.

## D1. Backend: a native C FastCGI responder in a lighttpd pool

**Status:** approved by the user (2026-10-10, plan).

`STEWARD.EXE -b 127.0.0.1:<port>`, one detached process per pool member, restarted by a
DCL loop. This is the same shape as vms-lighttpd's `PHP_POOL.COM`: LOGINOUT
`/DETACHED`, process name per port, a stop file ending the loops, and lighttpd's
`fastcgi.server` listing the same host:port pairs. Each process handles one request at a
time. We implement the FastCGI responder protocol ourselves (it is small) rather than
port libfcgi.

Alternatives: PHP on vms-php (cannot call system services without a C extension, so it
is C anyway plus a PHP dependency); VSI Python (needs a Python install and ctypes or C
bindings, and each worker is heavier).

## D2. Authorization: SYS$ACM login, per-request persona

**Status:** approved by the user (2026-10-10, plan). Mechanism to be confirmed by the
Phase 0 probes.

The password is checked by `SYS$ACM` (authenticate principal), which applies the system's
own policy: expiry, DISUSER, login hours, intrusion detection. Each API request then
creates the caller's persona and assumes it for the duration of the work, so the OS
enforces privileges and protection (SYSPRV for the UAF, rights database ownership,
and so on). The service account needs IMPERSONATE (and whatever ACM additionally
requires), not SYSPRV or CMKRNL.

Alternative: a privileged service with its own role checks against a rights identifier.
It is simpler, but every authorization decision is then our code and a bug is a
privilege escalation.

## D3. Targets and compiler: x86-64 first, VSI C with 32-bit pointers

**Status:** x86-64 first approved by the user (2026-10-10, plan). Compiler revised from
clang to VSI C during Phase 0 (2026-10-10); confirm at the Phase 0 exit.

The plan said clang, as for vms-php and vms-mariadb. Those need LP64 because their
upstreams assume `size_t` is pointer-sized. Steward has no such upstream, but it calls
system services heavily, and their item lists (`ILE3`) and descriptors are 32-bit
structures. VSI C's `/POINTER_SIZE=32`, with `SSL3$LIBCRYPTO_SHR32`, is the combination
vmsguard has proven on both x86-64 and IA64 (vmsguard `build_vms.com`). The code stays
C99 (`-std=c99 -pedantic` on Linux).

## D4. Front end: vanilla ES modules, no build step

**Status:** approved by the user (2026-10-10, plan).

Static `index.html`, ES modules and CSS served by lighttpd. There is no npm and no
bundler, so deploying is a file copy and there are no dependencies to keep patched.
Alternative: Vue/React built with Vite on Linux, which gives a richer UI but brings a
toolchain and dependency churn.
