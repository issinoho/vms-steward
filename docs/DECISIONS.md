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
and so on). The service account holds IMPERSONATE, plus SYSPRV authorized only for
persona creation (amendment below). It never holds CMKRNL or SECURITY.

**Amended 2026-10-10 (user's choice): the service account also holds SYSPRV,
authorized but not default.** `$PERSONA_CREATE` reads the user's UAF record under
`$GETUAI`'s rules: GRPPRV within the service's UIC group, SYSPRV for everyone else
(docs/PHASE1.md). Steward enables SYSPRV in its own identity only around that call and
disables it before assuming the persona. If disabling fails it exits, and after every
request it checks that SYSPRV is off and exits if not. The user's persona never
inherits it: a persona's privileges come from that user's own record (probe_setprv).
To be clear about the risk: IMPERSONATE already lets the service become any user,
SYSTEM included, so SYSPRV adds little to what a compromised service could do. The
real controls are the checks in front of persona creation.
Rejected: an ACL on SYSUAF (unproven that `$PERSONA_CREATE` honours it, and it exposes
password hashes to the account); SYSPRV as a default (on for any path outside a persona).

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

## D8. Strict security auditing of the code

**Status:** required by the user (2026-10-10).

Every change is audited by machine, and every phase by a person, against a written
threat model (`docs/security.md`):
- **Continuously** (`make audit`, and CI on every push): GCC `-fanalyzer` with
  warnings as errors, cppcheck, flawfinder, Semgrep, gitleaks, project-specific rules
  (`tools/audit_rules.sh`), the API suite under ASan/UBSan, and parser fuzzing.
- **At every phase exit, as a gate:** threat-model update, line-by-line review
  against the checklist, VMS-side checks (link severity, image privileges, file
  protections, service-account privileges), and findings recorded with a regression
  test that fails without the fix.
- **Before the first release:** independent external review of the
  authentication, session and persona code, and a penetration test behind nginx
  proxy manager.

The checks are verified to fail when they should. The project rules and the
analyzer were each shown a planted violation; the analyzer step had been a no-op
under `-fsyntax-only` until that test.

## D9. Enabling authorized privileges: opt-in per session

**Status:** approved by the user (2026-10-10): option A. Built in Phase 1.

A persona starts with the user's **default** privileges and may enable any **authorized**
privilege with `$SETPRV` (docs/PHASE1.md). Administrators often hold SYSPRV as authorized
but not default, deliberately, so that it is enabled only when needed. Steward should
respect that habit instead of silently enabling everything.

Proposal: the session holds a set of privileges the user has chosen to enable, starting
empty. The account page lets the user enable or disable authorized privileges, as
`SET PROCESS/PRIVILEGE` does, and each change is audited. Every request assumes the
persona and then `$SETPRV`s that set. OpenVMS refuses anything that is not authorized,
so the set cannot grant more than the user holds. An action refused for want of a
privilege that is authorized but not enabled says which one to enable.

Alternatives:
- Enable every authorized privilege on every request. Simple, but it removes a
  safeguard the site chose.
- Defaults only, with no way to enable more. Users whose SYSPRV is authorized only
  could not administer anything.

## D10. Read views show what OpenVMS shows, no more and no less

**Status:** approved by the user (2026-10-10): keep as built. Phase 2.

Phase 2 found two places where OpenVMS is more open than its file protections
suggest (docs/PHASE2.md):
- anyone may read the rights database through `$IDTOASC`, `$FIND_HELD` and
  `$FIND_HOLDER`;
- `$GETUAI` says "record not found" for a missing user before it checks privilege,
  so a signed-in user can tell whether a username exists.

Decision: Steward passes on exactly what OpenVMS returns to the caller's persona.
It adds no access rules of its own and does not mask the OS's answers. A user sees
in Steward what they could see at a terminal.

Why: D2 makes OpenVMS the single authority. A second, Steward-only rule set would
drift from the system's, would need its own review, and would not stop anyone, since
the same facts are available from DCL. Before sign-in nothing changes: every
sign-in failure still looks the same (Phase 1).

Alternatives:
- Treat RNF as 403 for callers without SYSPRV. This hides little (MAIL and the
  rights database already reveal usernames), and it would make Steward's answers
  differ from the system's.
- Require SYSPRV for the identifier views. Stricter than OpenVMS, for no gain.

## D11. Password changes: check the current password the way sign-in does, first

**Status:** taken in Phase 3 (2026-10-11), from a probe finding.

`$ACM CHANGE_PASSWORD` checks the current password itself, but a failed check is
charged to the **account** (a `USERNAME` intrusion record), even when a client
address is given. A failed sign-in (`AUTHENTICATE_PRINCIPAL`) is charged to the
**client** (PHASE1.md, PHASE3.md). If the change endpoint called CHANGE_PASSWORD
directly, anyone could guess at it and push any account into break-in evasion,
locking its owner out everywhere.

Decision: `POST api/v1/session/password` first authenticates the current password as
sign-in does, with the browser's address as the remote host. Only after that succeeds
does it call CHANGE_PASSWORD. Wrong guesses are then charged to the guesser's
address, as at sign-in, and a wrong username or password looks exactly like a
failed sign-in. The endpoint is public, because a user whose password has expired
cannot sign in until they change it, and the current password is the
authentication.

An administrator setting someone else's password (`POST api/v1/users/{u}/password`)
uses `$SETUAI UAI$_PASSWORD` under their persona instead. The system hashes it and
applies the minimum length, and OpenVMS requires SYSPRV, as for AUTHORIZE.

Alternatives:
- CHANGE_PASSWORD alone: simpler, but it hands an account-lockout lever to the
  internet.
- Change passwords only when signed in: an expired password could then never be
  changed through Steward, which is the dead end Phase 1 left.

## D12. The dashboard: fastfetch's figures, read as you, refreshed without keeping sessions alive

**Status:** taken 2026-10-11, at the user's request ("a dashboard landing page ...
the information which we gathered from vms-fastfetch").

- **The data:** the same system services and findings as vms-fastfetch. These are
  `$GETSYI`; `$GETRMI` for memory lists, CPU idle ticks and process states;
  `$DEVICE_SCAN` with `$GETDVI`; a wildcard `$GETJPI`; and a wildcard `$GETQUI`. They
  are reimplemented in `st_plat_vms.c`, keeping fastfetch's lessons: buffer sizes,
  the `$GETQUI` status, and the disks to skip. Not included: the PCSI product count
  (fastfetch spawns `PRODUCT SHOW PRODUCT`, too heavy for a pool process) and the
  CPU model name (it needs a clang-compiled CPUID helper; fastfetch D11).
- **Read as you** (D2, D10). Nothing needs privilege, but the process scan shows only
  what your persona may see, and the rest is counted as hidden and said so.
- **CPU usage** is computed in the browser from two readings of the idle counter, so
  no request holds a pool process for a sampling interval.
- **Refreshing:** every 10 s, and not while the tab is hidden. Polls are marked
  `X-Steward-Background: 1` and do not refresh the session's idle clock; otherwise
  a dashboard left open would never sign out.

Alternatives: sampling CPU in the request (holds one of the pool's two processes for
the interval, per viewer); counting polls as activity (defeats the idle timeout); a
server-side cache shared by viewers (shows one persona's view to another, against D2).
