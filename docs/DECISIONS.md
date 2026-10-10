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

**Status:** approved by the user (2026-10-10, plan). Confirmed by the Phase 0 probes
(docs/PHASE0.md #4, #5), with two additions below.

The password is checked by `SYS$ACM` (authenticate principal), which applies the system's
own policy: expiry, DISUSER, login hours, intrusion detection. Each API request then
creates the caller's persona and assumes it for the duration of the work, so the OS
enforces privileges and protection (SYSPRV for the UAF, rights database ownership,
and so on). The service account needs IMPERSONATE (and whatever ACM additionally
requires), not SYSPRV or CMKRNL.

Additions from Phase 0:
- Non-dialogue `$ACM` accepts a pre-expired password, so Steward checks expiry itself
  (UAI flags and password date/lifetime) and refuses the session until the password is
  changed.
- Intrusion records name the calling process unless told otherwise. Steward passes the
  client IP as `ACME$_REMOTE_HOST_NAME` and `STEWARD` as `ACME$_REMOTE_USERNAME`, which
  gives one record per browser address (docs/PHASE1.md). Breakin evasion then works
  per client, and Steward keeps no rate limiter of its own.
- Usernames are upcased and validated before `$ACM` or `$PERSONA_CREATE` (persona
  creation accepts lowercase as given).

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

## D5. JSON: an in-house parser and writer

**Status:** taken in Phase 1 (2026-10-10). Open to review.

`src/core/st_json.c`, about 450 lines. It is strict RFC 8259: duplicate keys, NUL,
lone surrogates and invalid UTF-8 are refused. Nesting is limited to depth 32 and 4096
items per container, and decoded strings are scrubbed on free because they carry
passwords. The writer takes ISO-8859-1 (what OpenVMS stores) and emits UTF-8, escaping
`<`, `>` and `&`. It is unit-tested and mutation-fuzzed (`make fuzz`) under ASan and UBSan.

Alternative: vendoring cJSON (MIT). It is mature, but it accepts duplicate keys and does
no character-set conversion, so it would need wrapping, and it would be a second
codebase to keep C99/VSI C clean.

## D6. Creating and deleting users

Reserved for Phase 4 (see the plan).

## D7. Reverse proxies: nginx proxy manager in front of lighttpd

**Status:** required by the user (2026-10-10).

The site must work behind nginx proxy manager (NPM): TLS ends at NPM, which then
connects to lighttpd. lighttpd's view of the request is then the proxy's, so Steward
reconstructs the browser's view from `X-Forwarded-*`. It does so **only when the
connection comes from a configured trusted proxy** (`STEWARD_TRUSTED_PROXIES`:
addresses and IPv4 CIDR ranges). Otherwise any client could choose the address its
failed logins are charged to, and spoof the intrusion records D2 depends on.

- **Client address:** walk `X-Forwarded-For` from the right past trusted proxies, and
  take the first address that is not one of them. Anything to its left was written
  by the client and is ignored. This address goes to `$ACM` and the audit log.
- **Scheme and host:** from `X-Forwarded-Proto` and `X-Forwarded-Host` (NPM keeps `Host`
  anyway). These feed the same-origin check, which otherwise sees `http` while the
  browser says `https` and refuses every sign-in.
- **Mount point:** `X-Forwarded-Prefix`, if the proxy publishes the site under a path.
  The session cookie's path follows it, and the front end uses only relative URLs.
  The simplest setup is a host of its own at the root, which needs no prefix.
- Steward never builds absolute URLs, so there are no redirects to rewrite.
- Security headers that belong to the whole site (HSTS) are left to the proxy. The
  lighttpd fragment sets the page-level ones (CSP, frame denial), and the API sets its
  own (`no-store`, `nosniff`).
- The future terminal will use WebSockets; NPM needs "Websockets Support" turned on
  for the host.

Alternative: lighttpd's `mod_extforward`, which rewrites `REMOTE_ADDR` before Steward
sees it. It is a good second layer, but it would make Steward's security depend on a
web-server setting it cannot check. Steward also needs the scheme, host and prefix, which
mod_extforward does not provide.
