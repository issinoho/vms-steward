# vms-steward: plan

## Context

VSI WebUI (products.vmssoftware.com/webui) gives OpenVMS a REST API and a browser UI for
users/rights, processes, queues, logicals, SYSGEN, licences, products, monitoring, error
log and a terminal. It is commercial and unreliable. We are building our own from scratch
(not a port) as a new member of the vms-* family. It runs behind **vms-lighttpd**
(HTTPS terminates there) as a FastCGI service with a static browser front end. We start
with the scaffolding plus one use case, **users and rights identifiers**, and add the other
areas only once that is proven stable.

Name: **vms-steward** (D0), with logical `STEWARD$ROOT`, image `STEWARD.EXE` and PCSI
producer ISSINOHO. It is deliberately unlike "WebUI" so it can't be confused with VSI's
product.

## Decisions (details in DECISIONS.md)

- **D1 Backend:** a native C FastCGI responder, `STEWARD.EXE -b <addr:port>`, run as a pool
  of detached processes by vms-lighttpd exactly as `PHP_POOL.COM` runs PHP. It speaks the
  FastCGI protocol itself, with no libfcgi.
- **D2 Authorization:** persona impersonation. Login goes through `SYS$ACM`, which honours
  passwords, expiry, DISUSER and intrusion detection. Each request then does
  `$PERSONA_CREATE(user)` → `$PERSONA_ASSUME` → work → revert/delete, so the OS enforces
  SYSPRV, rights DB protection and the rest. The service account holds IMPERSONATE (plus
  whatever Phase 0 shows ACM needs) and nothing else. This also means "who may manage
  users" is just VMS privilege, with no parallel RBAC.
- **D3 Targets:** x86-64 first, built with VSI C, `/POINTER_SIZE=32` and
  `SSL3$LIBCRYPTO_SHR32`, which is vmsguard's proven combination. This was revised from clang
  during Phase 0 because system-service item lists are 32-bit structures. The code is C99
  so IA64 stays cheap later. (The IA64 port was tried on 2026-10-16 and is on hold:
  docs/IA64.md.)
- **D7 Reverse proxies:** must work behind nginx proxy manager. `X-Forwarded-*` is
  believed only from configured trusted proxies, and the front end uses relative URLs.
- **D8 Security auditing of the code:** `make audit` and CI on every push (analyzers,
  sanitizers, fuzzing, project rules), a security review gate at every phase exit, and
  an independent external review before the first release (docs/security.md).
- **D4 Front end:** vanilla ES modules with no build step and no npm. Static files are served
  by lighttpd, and the deploy is a file copy.

## Architecture

```
browser ──HTTPS──> vms-lighttpd ──static──> [WWW] index.html, js/, css/
                        │ /api/v1/*  (mod_fastcgi, 127.0.0.1)
                        v
            STEWARD.EXE pool (N detached processes, 1 request at a time each)
              core/   fcgi framing, HTTP req/resp, router, JSON, validation, errors
              svc/    use-case handlers (users, identifiers, session)
              plat/   st_platform.h  -> vms/ (system services) | stub/ (Linux fake)
```

- **Layering (vmsguard's rule):** `core/` does no I/O and is fully unit-tested on Linux.
  `plat/st_platform.h` is the whole OS surface: auth, persona, UAF get/set/enumerate,
  identifier and holder operations, message text, RNG/HMAC. It must stay free of VMS types.
  `plat/stub/` is an in-memory fake UAF/rightslist, so the whole service and UI run on
  Linux under the local lighttpd (`/etc/lighttpd` exists) for fast front-end work and
  integration tests.
- **Sessions:** a 256-bit random id in a cookie that is `Secure; HttpOnly;
  SameSite=Strict; Path=/api`. Sessions live in a small RMS indexed file shared across pool
  processes and keyed by SHA-256(id), holding user, created, last-seen, idle and absolute
  expiry. That makes logout and revocation real. Mutating methods also require the
  `X-Steward-CSRF` header to match the token returned at login. Passwords are never logged
  or stored.
- **Errors:** every VMS condition maps to an HTTP status and an RFC 9457 problem+json body
  carrying the `$GETMSG` text and the condition value. For example, NOPRIV → 403 and
  NOSUCHUSER/NOSUCHID → 404.
- **Audit:** every mutating call appends a record (who, what, target, before/after, status)
  to `STEWARD$ROOT:[LOG]AUDIT.LOG`. OPCOM/`$AUDIT_EVENT` comes later.
- **JSON:** an in-house writer, plus either a vendored MIT parser (cJSON) or a small
  in-house one. That choice is D5, made in Phase 1. The parser is fuzzed on Linux either way.

## REST API v1 (use case 1)

| Method & path | Purpose |
|---|---|
| `POST /api/v1/session` · `GET` · `DELETE` | login (ACM) / whoami+privs / logout |
| `GET /api/v1/users?start=&limit=&filter=` | list (username, UIC, owner, flags, last login) |
| `GET /api/v1/users/{u}` · `PATCH` | detail / modify (flags, expiry, owner, account, defaults, quotas, privs) |
| `POST /api/v1/users/{u}/password` | set password (+ pre-expire option) |
| `GET /api/v1/users/{u}/identifiers` · `POST` · `DELETE …/{id}` | held identifiers, grant, revoke |
| `GET /api/v1/identifiers` · `POST` · `GET/PATCH/DELETE /{id}` | rights DB: list, create, rename/attributes, delete |
| `GET /api/v1/identifiers/{id}/holders` | holders |
| `POST /api/v1/users` · `DELETE /api/v1/users/{u}` | create/copy/delete user (Phase 4, mechanism per D6) |

The API is versioned in the path and documented in `docs/api.md`. Its shape is chosen so
the future areas (`/processes`, `/queues`, `/logicals`, `/sysgen`, ...) slot in as further
`svc/` modules.

## Repository layout (`~/projects/vms-steward`, git, origin github.com/issinoho/vms-steward)

```
CLAUDE.md  README.md  Makefile  build_vms.com      (one VMS build file only: vmsguard lesson)
docs/      PLAN.md DECISIONS.md NOTES.md PHASE0.md api.md security.md
src/core/  st_fcgi.c st_http.c st_router.c st_json.c st_valid.c st_problem.c
src/svc/   svc_session.c svc_users.c svc_idents.c
src/plat/  st_platform.h  vms/st_plat_vms.c  stub/st_plat_stub.c
src/main/  steward_main.c   (FastCGI accept loop, pool-friendly)
www/       index.html  js/{app,api,router,views/*}.js  css/
tests/     unit (C), api (Python against Linux lighttpd + stub), e2e smoke vs <x86-host>
probes/    small C/DCL probes        tools/ vms.sh nodes.conf.example push.sh build.sh
vms/       STEWARD_POOL.COM  STEWARD$STARTUP.COM  steward.conf
```

Reuse: copy `tools/vms.sh`, `nodes.conf.example` and the push/build pattern from
`~/projects/vms-php/tools/`. Copy vmsguard's Makefile flags (`-std=c99 -pedantic -Wall
-Wextra`) and its testing conventions. CLAUDE.md carries over the family ground rules: no
real node details or credentials committed, use vms.sh rather than raw ssh, run long jobs
in the background, nothing system-wide on nodes without asking, and leave the live
board's lighttpd alone.

## Phases (stop and review with you at each exit)

Every phase exit includes the security gate in docs/security.md (D8): threat-model
update, a checklist review of every changed file, VMS-side checks, and findings with
regression tests. A phase does not close until it passes.

**Phase 0: scaffolding and probes.** Create the repo, CLAUDE.md, docs and tooling. Then
answer with probes on `<x86-host>` rather than speculation:
- the ACM non-interactive authenticate call, and what privileges it needs;
- `$PERSONA_CREATE`/`ASSUME` from a detached process, and checking `$GETUAI`/`$SETUAI` under
  a non-privileged versus a SYSPRV persona;
- UAF enumeration, i.e. RMS sequential key read of SYSUAF plus `$GETUAI`;
- `$IDTOASC` wildcard enumeration, `$FIND_HOLDER` and `$ADD/REM_HOLDER`;
- the SSL3 RNG/HMAC/SHA-256 images under clang;
- an FCGI socket bound and reached by vms-lighttpd's pool mechanism.
vms-lighttpd's `PHP_POOL.COM` (in its vmsport tree on the node) is the pool pattern to
follow. Exit: `docs/PHASE0.md` with each question answered.

**Phase 1: platform skeleton.** FastCGI responder, router, JSON, problem errors, sessions,
login/whoami/logout, CSRF and audit plumbing, all running on both stub and VMS
platforms. The UI has a login page and an app shell (nav, toasts, error display). The
lighttpd fragment, pool procedure and startup procedure come here too. Exit: on x86 over
HTTPS you can log in, see whoami with your privileges, and log out. Bad password, DISUSER
and expired password are all rejected, with intrusion detection observed. The Linux unit
and API suites pass, and the FCGI and JSON parsers have been fuzzed.

**Phase 2: users and rights, read-only.** List, filter and page users. User detail and held
identifiers. Identifier list, detail and holders. Exit: results match `AUTHORIZE SHOW`
and `SHOW /RIGHTS`/`LIST/IDENT` for a sample set, and a non-privileged login correctly
gets 403 or reduced data.

**Phase 3: users and rights, modify.** PATCH user fields and flags, set password, grant
and revoke, create/modify/delete identifiers, all with audit records and optimistic
concurrency (an ETag from the record). Exit: each operation is verified against AUTHORIZE
output, a NOPRIV persona is refused by the OS rather than by our code, and the audit log
is complete.

**Dashboard (2026-10-11, D12).** The landing page after sign-in: the system at a glance,
with the figures vms-fastfetch shows, read as the user, refreshed in the background.

**Phase 4: create, copy and delete users.** No system service creates UAF records, so D6
chooses between an RMS `$PUT` to SYSUAF (what AUTHORIZE does) and driving AUTHORIZE in a
subprocess, based on the Phase 0 probe. Deleting a user also covers the identifier.
Exit: round-trip create, copy and delete, consistent with AUTHORIZE.

**Phase 5: hardening and kit** (closed 2026-10-11 on the user's approval; see PHASE5.md. Open: an independent code review and the external review and penetration test). Load run with no crashes or leaked personas, idle and
absolute session expiry, security review (headers, CSP, cookie flags, input limits),
PCSI kit and startup, README status table, and the independent external review and
penetration test (D8). Exit: the kit is installed on x86, and you run
it before we declare use case 1 stable.

**Phase 6: access history** (the user's priority among later areas, 2026-10-10;
closed 2026-10-11, released as 0.4.0). One view of who reached the system, when, from
where and by which route. As built (D13), there is no collector: each request reads
accounting, the security audit journal, OpenSSH's logs, Steward's own log and the
live process list, under the viewer's persona, and merges them. See `docs/PHASE6.md`.

**Phase 7: logical names** (D14, D15). 7a, read-only, closed 2026-10-13 on the user's
browser checks and an independent review of the whole phase, released as 0.5.1. 7b,
define and deassign, closed 2026-10-15 on the user's browser checks, a review and the
shadowing probe (0.6.2). See `docs/PHASE7.md`.

**Phase 8: processes** (D16): read-only (8a) and stopping a process (8b) closed
2026-10-15 on the user's browser checks and a review (0.7.2). See `docs/PHASE8.md`. See `docs/PHASE8.md`.

**Phase 9: batch and print queues** (D17): read-only (9a) and changes (9b: hold,
release, delete a job; stop and start a queue) closed 2026-10-15 on the user's browser
checks and a review (0.8.1). See `docs/PHASE9.md`. See `docs/PHASE9.md`.

**Phase 10: system parameters** (D18), closed 2026-10-16 on the user's browser checks
(0.9.0): read-only, SYSGEN SHOW/ALL in the D14 helper. See `docs/PHASE10.md`.

**Phase 11: licences** (D19): read-only, SHOW LICENSE and LICENSE LIST in the D14
helper. Closed 2026-10-16 on the user's browser checks and a review of this phase
and Phase 10's shared helper (0.10.1). See `docs/PHASE11.md`.

**Phase 12: installed products** (D20). 12a, read-only, closed 2026-10-17 on the
user's browser checks (0.11.0): PRODUCT SHOW PRODUCT/FULL and HISTORY/FULL in the D14
helper (the account needs SYSLCK authorized; PRODUCT switches it on), and VMSINSTAL's
history read in-process. 12b (install and remove) not yet decided. See
`docs/PHASE12.md`.

**Phase 13: monitoring** (D21). 13a, read-only, closed 2026-10-17 on the user's
browser checks (0.12.0): `$GETRMI` counters, readable by anyone, polled by the page
(5 s by default), history kept in the browser for 30 minutes, and the busiest
processes among those the viewer may see. 13b (history recorded on the node by a recorder process, D22 proposed) being
planned: questions in `docs/PHASE13.md`, which is where to pick up.

**Later areas, one at a time and each with the same read-only → modify split:** licences, installed products,
CPU/memory monitoring, error log, and a WebSocket terminal (lighttpd `mod_wstunnel`); licences are Phase 11.
The user confirmed this order on 2026-10-11 (licences stay where they are).

**Wish list (not scheduled):** a layout made for phones (`docs/ideas/mobile.md`,
asked for by the user 2026-10-11).

## Verification

- `make test`: C unit tests for the core (FCGI framing, HTTP parsing, router, JSON,
  validation, condition→HTTP mapping), plus fuzz targets for the FCGI and JSON parsers.
- `make api-test`: Python tests drive the real `steward` binary on the stub platform
  behind the local lighttpd over HTTPS, covering login, CSRF, the session lifecycle and
  every endpoint.
- On `<x86-host>` via `tools/vms.sh`: `@build_vms TEST` runs the same core unit tests
  natively. A smoke script then exercises the API through vms-lighttpd against a test
  account and compares the results with AUTHORIZE output.
- Each phase exit is recorded in docs/NOTES.md with the commands and the output observed.
