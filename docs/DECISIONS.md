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

**IA64 (2026-10-16):** the same sources build unchanged on IA64 V8.4-2L3 with VSI C
V7.4-001, and the native unit tests pass (NOTES.md). The one difference found in the
headers, the longest password, is taken from the headers of the build node
(`st_plat_password_max`, `UAI$C_MAX_PWD_LENGTH`), not hard-coded: the kit is built on
the architecture it ships for, so that is the target's value. Alternatives: a run-time
probe (there is no service that reports it, and `$HASH_PASSWORD` takes any length), or
64 everywhere and leave it to `$SETUAI` (unverified on IA64, and the message would be
wrong). The browser's input fields stay at 64; the service's 422 names the real limit.

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

## D6. Creating and deleting users: RMS on SYSUAF, as AUTHORIZE does, under the persona

**Status:** decided 2026-10-11 from the Phase 4 probes (PHASE4.md).

No system service creates or deletes a UAF record. Steward does what AUTHORIZE does:

- **Create and copy** read a template record: DEFAULT for a new user (AUTHORIZE ADD's
  defaults), or the source user for a copy. Steward copies it and changes the
  username, UIC and owner, clears the password and login history, and `$PUT`s it to
  SYSUAF. It then sets the password with `$SETUAI` (hashed by the system, minimum
  length enforced) and any other fields through the same path as a modify, and adds
  the UIC identifier with `$ADD_IDENT`. If a step after the `$PUT` fails, Steward
  removes what it added, so a create either completes or leaves nothing behind.
- **Delete** revokes the user's holdings, removes the UIC identifier, then deletes the
  record: AUTHORIZE REMOVE's result, verified identical by probe.
- **Layout** comes from UAFDEF's struct in `SYS$LIB_C.TLB`, so the compiler computes
  the offsets from the system's own definition. This is the one place Steward
  handles a raw system record. It is the system's record, so the system's
  definition is the right authority, rather than offsets copied by hand.
- **All under the persona.** Writing SYSUAF needs SYSPRV, and OpenVMS refuses anyone
  without it. Steward adds no rule of its own (D2, D10).
- **Safety rails, not access control:** Steward refuses to delete the account you are
  signed in as, or the service account, either of which would cut off Steward
  itself. It refuses a UIC that another *user* already has: AUTHORIZE only warns
  about this, but two users sharing a UIC share files and processes. A delete must
  carry the ETag of the record shown, so you delete what you looked at.

Alternatives:
- **Run AUTHORIZE in a subprocess.** It is the reference implementation, but the pool
  would have to spawn processes per request. Usernames and owners would have to be
  quoted safely into a DCL command line (an injection risk), its output would have
  to be parsed for errors, and a spawned subprocess's identity under a persona
  needs its own proof.
- **Build the record from nothing.** More fields to get right than copying the
  template AUTHORIZE itself uses.

## D13. Access history: read the sources on demand, as the viewer

**Status:** approved by the user 2026-10-11 ("read on demand, as you"). Phase 6.

One view of who reached the system, when, from where and how, merged at request
time from:
- **accounting** (finished sessions: interactive, network, batch; login failures
  seen by LOGINOUT);
- the **security audit journal** (LOGFAIL and BREAKIN, including failures through
  `$ACM`);
- **OpenSSH's per-connection logs** (authentication method and key, failed attempts);
- **Steward's own audit log** (sign-ins through Steward);
- **the live process list** (who is connected now).

Each is read with the record layouts from the system's own headers (ACRDEF,
NSAMSGDEF), under the viewer's persona. OpenVMS decides, source by source, whether
the viewer may read it. A refused source is reported as refused, and the rest are
still shown.

Why: it needs no new account, process or privileged reader (D2), and nothing to keep
in step. The cost is that history goes back only as far as each source does:
accounting and the journal since their last rotation, and SSH logs until they are
purged. Reads are bounded by a time window and an event cap.

Alternatives: a collector process under its own privileged account writing a store
of its own (durable history, but a second privileged component to secure, and data
copied outside OpenVMS's own controls); enabling LOGIN auditing to use the journal
alone (not needed: accounting already records successful sessions).

**Amended 2026-10-16 (user's choice, "bound + faster", then the probe's finding): the
SSH logs are looked up by name, and any search of them is bounded.** On IA64,
`SSH$ROOT:[VAR]` held 27,409 logs and one request took 1,579 s; a probe showed the cost
was the directory walk itself, not opening the logs, so reading dates from file
headers (the first plan) would not have helped (NOTES.md). Each SSH connection that
accounting gives is now opened by its exact name, `<node>_<host>_<pid>.LOG` (a dot
escaped as `^.`; a host with any other character outside letters, digits, `-` and `_`
gets no name). Only connections with no usable name (live ones, which carry no remote
full name; unusual hosts) or every log, when accounting is refused, need the wildcard
walk, and it stops after 5 seconds. A source read but not to the end is reported
`"complete": false`, and the page says what that means and that purging old logs fixes
it. Alternatives: walk everything with a budget only (on a crowded node every request
would lose the SSH detail); leave it to the site to purge (the problem returns as logs
accumulate).

## D14. Logical names: list tables through a short-lived detached process, as the viewer

**Status:** approved by the user 2026-10-11 (option A). Phase 7.

OpenVMS has no service that lists the names in a table: `$TRNLNM` translates a name
you already know, and STARLET exports nothing that enumerates. `SHOW LOGICAL` can list
them because DCL calls internal routines. So, to **list** a table, Steward creates a
**detached** process running LOGINOUT on a fixed procedure, `STEWARD_LNM.COM`. It
creates it while the viewer's persona is assumed, so the process *is* the viewer: same
UIC, same privileges. It runs `SHOW LOGICAL/FULL` and OpenVMS decides what it shows
(D2).
- **Data only:** Steward passes the table and the pattern as data, through a request
  mailbox. The procedure reads them, checks every character against
  `A-Z 0-9 $ _ * %`, and writes the listing to a reply mailbox. Its process name gives
  the two mailbox units: `STW<request>_<reply>` until 2026-10-15, now
  `STW<request><reply><random>`, 4 hex digits each, so a member of the viewer's group
  cannot create the names ahead. Steward never writes a command.
- **Owner only:** both mailboxes are created under the persona with protection for
  system and owner only.
- **Everything else in-process:** translating one name (`$TRNLNM`), and later defining
  and deassigning (`$CRELNM`, `$DELLNM`), run in-process under the persona, as every
  other request does.

Why: it is the only way found to list what the viewer may see, with OpenVMS deciding.
Listing as the service and filtering each name by `$TRNLNM` under the persona (option
B) would miss tables the service account cannot read: other groups' tables, even for
a viewer with SYSPRV. It would also let the service's view shape the answer.

Cost: about 0.12 s per listing to create the process and log in, plus the listing. Each
listing is a short detached "login" of the viewer (accounting shows it; access history
ignores detached processes). It counts against the viewer's detached-process and job
limits while it runs. The system and the user's login procedures run, as for any
detached process.

Found by probe (`probes/probe_lnm.c`, PHASE7.md), each of these refused:
- `LIB$SPAWN` under a persona is always `%SYSTEM-F-NOPRIV`.
- A `$CREPRC` *subprocess* runs as the persona but waits for context only LIB$SPAWN
  sends.
- With a mailbox as input, LOGINOUT takes it for a terminal and waits at a sign-in
  prompt.
- DCL refuses a mailbox as SYS$OUTPUT (`%RMS-F-DEV`), so the procedure writes the
  listing with `SHOW LOGICAL/OUTPUT=`.
- **One name, only in a table (2026-10-13).** `GET logicals/{table}/{name}` refuses
  LNM$SYSTEM_DIRECTORY with a 404, on VMS as the stub already did. The directory has
  the table attribute, so it passed the "real table" check, but its names are tables:
  `GET logicals/tables` lists them, and a translation there (LNM$FILE_DEV, say) would
  only show a search list the other endpoints refuse. Refusing it keeps one rule for
  every single-name lookup rather than relaxing the live test.
- **Job tables refused by name too (2026-10-13, the user's decision).** Any
  `LNM$JOB_<address>` is refused for listing and lookup, as `LNM$JOB` is. The tables
  list still shows them, not listable. One of them is the pool process's job's, and
  Steward cannot tell a viewer's job from the service's. The alternative, leaving the
  check to OpenVMS's protection on the table, was not probed for the in-process
  `$TRNLNM` under a persona in the service's own job table.
- **The helper is fixed, and watched three ways (2026-10-13, the Phase 7 review).**
  Its path is a constant: a logical-name override would be translated through the
  service's group and system tables, which others can define. Steward waits on the
  reply, the deadline and a termination mailbox together, and checks the deadline
  after every wake, so neither a helper that floods the reply nor one that dies holds
  a pool process. A listing over 100,000 messages is refused.
- **And resolved before it is handed over (2026-10-13, Phase 7b probe).** The helper
  translates the path it is given in its own context, where the viewer's group table
  and outer-mode system names come first (NOTES.md). So the pool resolves it once at
  start-up, as the service, to a physical device and a full directory, and passes
  that.

## D15. Logical names: define and deassign in-process, refusing what OpenVMS would quietly change

**Status:** tables, modes and replacing approved by the user 2026-10-13; the rest
follows from the probe (`probes/probe_crelnm.c`, NOTES.md). Phase 7b.

Defining (`$CRELNM`) and deassigning (`$DELLNM`) run in-process under the persona, as
D14 planned. OpenVMS checks the persona's privileges and the table's protection (the
probe: my all-privileged process, STEWARD_TEST's persona, NOPRIV). On top of that:
- **Tables:** any table the read-only endpoints can list. A table in
  LNM$SYSTEM_DIRECTORY with the table attribute, not the directory, never a process or
  job table (`st_valid_lnm_table`), and `LNM$GROUP` named as the viewer's group table:
  under a persona it would be the service's.
- **Modes:** user, supervisor and executive, as DEFINE offers. Kernel is refused.
  Without SYSNAM, OpenVMS would quietly use user mode for an inner mode, and replace a
  user-mode name the request never mentioned. So Steward refuses supervisor and
  executive with a 403 unless SYSNAM is switched on in the session (D9), before calling
  OpenVMS.
- **Replacing:** a define of a name that exists at that mode in that table is a 409
  unless the request says `"replace": true`. The browser shows the current value and
  asks first. The check and the define are two calls: a name defined in between is
  replaced, which is what `$CRELNM` does anyway.
- **Deassigning at a mode removes the name at that mode and every outer one**, as
  `$DELLNM` and DCL's DEASSIGN do. The answer lists the modes removed, and the browser
  names them before asking.
- **NO_ALIAS removes outer modes.** OpenVMS deletes the name at every outer mode when
  it defines it NO_ALIAS (NOTES.md). Steward lets it, as DEFINE does: the answer lists
  the modes left, and the browser names the ones that will go before it asks.
- **The audit log** records the table, the name, the mode and OpenVMS's answer, never
  the equivalences: logical names sometimes carry passwords or connection strings.
- **One name by query** (from the 7a review): `api/v1/logical?table=&name=` for GET,
  PUT and DELETE, so a name with `/` in it can be reached. The 7a path
  `logicals/{table}/{name}` stays for reading.

Alternatives not taken: letting OpenVMS downgrade the mode and reporting it afterwards
(the user-mode name would already be gone); `SET PROCESS/PRIVILEGE=SYSNAM` implied for
inner modes (D9: the session's privileges are the user's choice); a DEFINE in the D14
helper (in-process is simpler, and the probe shows OpenVMS checks the persona).

## D16. Processes: $GETJPI in-process, as the viewer; stopping by $DELPRC

**Status:** 8b's scope (stop only) and the probe's account changes approved by the
user 2026-10-15; the rest follows from the probe (`probes/probe_jpi.c`, PHASE8.md).
Phase 8.

Reading processes runs in-process under the persona, as every other request does:
wildcard `$GETJPI` for the list, `$GETJPI` by PID for one. OpenVMS skips (NOPRIV) each
process the persona may not see, so the list is the viewer's terminal view: their own
processes, their group's with GROUP, everyone's with WORLD. Steward adds:
- **Its own serving process is left out.** Under the persona it reports the viewer's
  username and UIC, so it would show as one of theirs. The pool's other processes are
  shown as they are (username STEWARD).
- **Refusals as OpenVMS gives them:** NOPRIV for a process the viewer may not see
  (403), NONEXPR for none (404), as `SHOW PROCESS/ID=` answers.
- **Stopping (8b)** is `$DELPRC` under the persona, refused for the service account's
  processes, confirmed in the browser and audited.

Alternatives not taken: listing as the service and filtering by the viewer's rights
(Steward would be deciding, not OpenVMS); `$PROCESS_SCAN` (filters by username,
mode and so on in the service, but adds nothing to who may see what, and the list is
small: 42 processes in 0.01 s on x86).
- **Stopping (8b, 2026-10-15, from `probes/probe_delprc.c`).** `DELETE
  api/v1/processes/{pid}` calls `$DELPRC` under the persona; OpenVMS checks the
  persona's UIC and GROUP/WORLD (the probe: NOPRIV from an all-privileged process
  without GROUP). It answers 202: the stop is asynchronous, as STOP/ID's is.
  - **Steward's own processes are refused** (409): any process of the service
    account, its pool, and any process running Steward's image (a worker busy with a
    request is reported under the requester's name: the Phase 8 review, NOTES.md),
    whatever privileges the viewer has. Stopping the pool from the
    browser would cut off the browser; at a terminal it stays possible.
  - **System processes are refused** (409, 2026-10-15, the user's decision): any
    process in a UIC group up to SYSGEN's MAXSYSGROUP (8 here: OPCOM, JOB_CONTROL,
    the ACPs, AUDIT_SERVER), whatever the viewer holds. In the 8b browser check
    STEWARD_ADM with WORLD stopped OPCOM, which D16 then allowed ("no other policy").
    At a terminal it stays possible. Other users' servers (lighttpd, MariaDB, TCP/IP
    services outside the system groups) stay stoppable as OpenVMS allows. The browser
    asks for the process name to be typed, as for deleting a user, and offers no Stop
    on a system process.
  - **Audited:** PID, process name, username and OpenVMS's answer.

## D17. Queues: $GETQUI and $SNDJBC in-process, as the viewer

**Status:** 9b's scope approved by the user 2026-10-15 (hold, release and delete a job;
stop and start a queue); the rest follows from the probe (`probes/probe_qui.c`,
PHASE9.md). Phase 9.

Queues and jobs are read with `$GETQUI` in-process under the persona. The queue
manager judges each request by the persona: a job the viewer may not read comes back
as inaccessible (entry and status only), as `SHOW QUEUE/ALL` shows it. Steward shows
it so too, and adds nothing. Changes will be `$SNDJBC` under the persona, once a probe
shows the queue manager judges those by the persona as well.

Alternatives not taken: driving SHOW QUEUE in a helper process (D14's way; not needed,
`$GETQUI` gives everything a terminal shows); reading as the service and filtering
(Steward would decide).
- **Changes (9b, 2026-10-15, from `probes/probe_sndjbc.c`).** Hold, release and delete a
  job, stop and start a queue, by `$SNDJBC` under the persona: the queue manager judged
  every one by the persona (JBC NOPRIV from an all-privileged process; the group may
  read a job but not change it; SYSPRV may). Steward refuses to stop SYS$BATCH and the
  queues it feeds, whatever the viewer holds (the user's choice after OPCOM): the pool
  is started at boot by a job there. Everything else is as the queue manager allows.

## D18. System parameters: SYSGEN SHOW/ALL in the D14 helper, read-only

**Status:** approved by the user 2026-10-15 (SYSGEN in the D14 helper; read-only for
now). Phase 10.

OpenVMS has no service that lists the system parameters with their defaults, limits,
units and dynamic flags; `$GETSYI` gives current values only. SYSGEN SHOW prints all of
it, and any user may run it (probe: STEWARD_TEST, unprivileged, in batch). So the D14
helper process, which is the viewer with the privileges switched on in the session,
runs a second fixed procedure, `STEWARD_SYSGEN.COM`: SYSGEN `SHOW/ALL`, written to the
reply mailbox, parsed in core (`st_sysgen.c`). The helper's machinery is shared
(`helper_run`); the procedure takes only the privileges as data.

Read-only: writing parameters needs CMKRNL and can keep a system from booting. Whether
to offer it (dynamic parameters in memory, or MODPARAMS.DAT for AUTOGEN) is decided
once this is in use.

Alternatives not taken: `$GETSYI` alone (no defaults, limits, units; Steward would need
its own list of parameter names); SYSGEN run by the service (it would be the service's
view, not the viewer's, D2).


## D19. Licences: SHOW LICENSE and LICENSE LIST in the D14 helper, read-only

**Status:** approved by the user 2026-10-16 (the loaded licences, the node's charge
and the database; changes decided later). Phase 11.

OpenVMS has no documented service that lists licences. The License Management
Facility shows two things: the licences loaded in memory (`SHOW LICENSE`, any user)
and the database of registered PAKs (`LICENSE LIST`, LMF$LICENSE, protection
`(S:RWED,O:RWED,G:RE,W:)`: OpenVMS lets the system category (a UIC up to MAXSYSGROUP,
SYSPRV), BYPASS, READALL and UIC group 1 read it; probe, PHASE11.md). So the D14 helper, which is
the viewer, runs a third fixed procedure, `STEWARD_LICENSE.COM`: `SHOW LICENSE/FULL`,
`SHOW LICENSE/UNIT_REQUIREMENTS` and `LICENSE LIST/FULL`, each to the reply mailbox and
each followed by its status, parsed in core. When the database is refused, the view
shows OpenVMS's refusal and the rest as usual (D10).

Read-only: registering, enabling and loading licences are decided once this is in use.

Alternatives not taken: reading LMF$LICENSE with RMS (its record layout is not
documented); the commands run by the service (its view, not the viewer's, D2).

## D20. Installed products: PCSI in the D14 helper, VMSINSTAL's history in-process

**Status:** approved by the user 2026-10-16 ("go with your suggestions", PHASE12.md):
SYSLCK authorized (not default) for STEWARD_ADM on x86 for testing, which the user
does; viewers without SYSLCK see PCSI's refusal, as the licence database's (D10);
VMSINSTAL's record shown as history, not as what is installed, since it never records
a removal; PCSI's history included beside the installed list; changes (12b) decided
later. Phase 12. Amended 2026-10-17: PRODUCT switches SYSLCK on itself, so an
account authorized for it reads PCSI whether or not it is switched on in Steward
(NOTES.md); D9 still holds for everything else.

PCSI's database has no documented interface, and `PRODUCT SHOW` needs SYSLCK (probe,
NOTES.md). So the D14 helper, which is the viewer, would run a fourth fixed procedure,
`STEWARD_PRODUCT.COM`: `PRODUCT SHOW PRODUCT/FULL` and `PRODUCT SHOW HISTORY/FULL` into
the reply mailbox (`DEFINE/USER SYS$OUTPUT`; PRODUCT has no `/OUTPUT=`), parsed in core.
VMSINSTAL's own record, `SYS$UPDATE:VMSINSTAL.HISTORY`, is a world-readable text file:
read in-process under the persona (as D13 reads its files) and parsed in core.

Alternatives not taken: reading the PCSI$*.PCSI$DATABASE files directly (format not
documented); the commands run by the service (its view, and its privileges, D2).

## D21. Monitoring: raw counters from the service, history in the browser

**Status:** approved by the user 2026-10-17 ("go", PHASE13.md): history in the browser
(30 minutes while the page is open), a 5 s interval with 2, 10 and 30 s to choose, the
busiest processes the viewer may see, and no per-CPU figures for now. Phase 13.

`$GETRMI` gives anyone the system-wide counters MONITOR shows (CPU modes, process
states, memory lists, paging, I/O), and `$GETDVI` each disk's operation count, without
privilege (probe, NOTES.md); nothing on the node records history. So `GET
api/v1/monitor` returns one reading of the raw counters, in-process under the persona,
with each process the viewer may see (as Phase 8); it keeps no state, so any pool
process answers it. The page polls while open, works out rates from consecutive
readings in a unit-tested JS module, keeps the last 30 minutes in memory and draws
MONITOR's classes as SVG charts.

Alternatives not taken (for now): a Steward sampler process on the node recording to a
file (history that survives, but a new long-running process; a possible 13b); MONITOR
/RECORD (system-wide, undocumented format); MONITOR in the D14 helper (a process a
reading, for counters open in-process anyway); per-CPU figures (`RMI$_MODES` layout
unsettled).

## D22. Monitoring history: a recorder process writing a fixed ring of raw counters

**Status:** proposed 2026-10-17 (PHASE13.md, 13b). Amends D21's "history in the
browser" for ranges beyond the live 30 minutes.

A detached `STEWARD_RECORDER` (the image as `STEWARD -r`), started and stopped with the
pool, running as the service account with IMPERSONATE and SYSPRV permanently off, takes
one `st_plat_monitor` reading each interval (60 s) and writes the system-wide raw
counters, no processes, into `[.RUN]MONITOR.DAT`: an RMS indexed file of fixed records
keyed by slot, a ring of fixed size (7 days). `GET api/v1/monitor/history` returns up to
P readings spread over a range by keyed reads; since the counters are cumulative, the
browser's `rates.js` gives exact averages between any two. The pool opens the file at
start as the service account, like the session store; anyone signed in may read it, as
anyone may call `$GETRMI` (D10). Processes are not recorded: what a viewer may see of a
process is `$GETJPI`'s answer as the viewer, which cannot be asked of one that ended.

Alternatives not taken: recording in a pool process by timer AST (could write under a
viewer's persona; every process would record); daily sequential files (grow, need
pruning, slow to seek); MONITOR /RECORD (system-wide, undocumented); recording rates
instead of counters (weighted averages, reboots inside an interval lost).
