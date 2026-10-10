# Phase 1: platform skeleton

## Probes (2026-10-10, x86 node)

### Intrusion source: closed (`probe_acm_host`)

Wrong-password attempts against `STEWARD_TEST`, each describing a client from
192.0.2.0/24 (RFC 5737), and then `SHOW INTRUSION`:

| Items passed | Intrusion source |
|---|---|
| `REMOTE_HOST_NAME "192.0.2.11"` | `192.0.2.11::IAIN` (the calling process's username) |
| `REMOTE_HOST_NAME` + `REMOTE_USERNAME "steward"` | `192.0.2.12::steward` |
| the same, logon type REMOTE instead of NETWORK | `192.0.2.13::steward` (still class NETWORK) |
| plus `REMOTE_HOST_ADDRESS` (4 bytes) + `_TYPE` (IPv4) | refused before authentication: BADBUFLEN in the ACMESB |

So Steward passes the client's IP from lighttpd (`REMOTE_ADDR`) as
`ACME$_REMOTE_HOST_NAME` and the constant `STEWARD` as `ACME$_REMOTE_USERNAME`. Each
browser address then gets its own record, and OpenVMS breakin evasion applies per
client, as it does for telnet. Steward needs no rate limiter of its own (this
supersedes the stop-gap noted in D2).

Notes:
- `ACME$_REMOTE_HOST_ADDRESS_TYPE` must be a **longword**. With a 2-byte buffer `$ACMW`
  itself returns BADBUFLEN, although the header comment says "16-bit". With a longword the
  service accepts the list, and then the VMS ACME rejects a 4-byte IPv4 address
  (BADBUFLEN in the ACMESB). We don't need the binary address, so this is not pursued.
- No attempt reached a password check while the item list was wrong, so the failed
  runs left no intrusion records.

### Privileges under a persona: mostly closed (`probe_setprv`)

Under the persona of an unprivileged account (TMPMBX, NETMBX), with the work process
itself holding every privilege, `$SETPRV` refuses GRPPRV and SYSPRV with NOTALLPRIV and
enables nothing. The persona's authorized mask is what limits `$SETPRV`; the process's
own privileges do not leak through. This is what D2 depends on.

**Pitfall found on the way:** `PRV$M_` masks for privileges 32-63 are 64-bit constants
(`PRV$M_GRPPRV` is `0x400000000`). Assigned to an `unsigned int`, the mask becomes 0, and
`$SETPRV` of an empty mask returns SS$_NORMAL. A request for GRPPRV therefore "succeeds"
while enabling nothing. Privilege masks are always carried as a full quadword.

Still open: whether a persona can enable a privilege that is authorized but not
default. That needs `STEWARD_TEST` given such a privilege, for example
`mcr authorize modify STEWARD_TEST /privileges=(tmpmbx,netmbx,grpprv)` with the default
privileges unchanged. Asked of the user, together with the service account.

### Expired passwords

Phase 0 showed that non-dialogue `$ACM` accepts a pre-expired password. The VMS
platform layer therefore checks, after a successful `$ACM`, `UAI$_FLAGS`
(PWD_EXPIRED, PWD2_EXPIRED) and `UAI$_PWD_DATE`/`UAI$_PWD_LIFETIME`, and reports an
expired password in place of a session. To be verified at the phase exit with
`STEWARD_TEST /PWDEXPIRED`.

## On OpenVMS (2026-10-10, x86 node)

- `@BUILD_VMS CLEAN` then `@BUILD_VMS TEST`: clean compile and link, TEST_CORE 75/75
  natively under VSI C V7.7-003.
- A two-process pool (`STEWARD_POOL.COM`) behind a **separate** test lighttpd
  (`LIGHTTPD_TEST.COM`: the installed VMSLIGHTTPD image with our own configuration on
  port 8443, kept away from the site's server). Checked from a Linux client:
  - the page gets `Content-Security-Policy`, `X-Frame-Options: DENY`,
    `Referrer-Policy: no-referrer` and `nosniff`; the JS modules are served as
    `text/javascript`, which module scripts require;
  - `GET /api/v1/health` returns 200 `{"status":"ok"}` with `Cache-Control: no-store`;
  - a wrong sign-in returns a generic 401 problem, and an unknown endpoint a 404 problem.
- Earlier, through an SSH tunnel to a single process: a wrong password for
  `STEWARD_TEST` from browser 192.0.2.99 left the intrusion record
  `192.0.2.99::STEWARD` and the audit record
  `outcome="failed" detail="%LOGIN-F-INVPWD, invalid password"`.

Still running as the work account, not the service account: the least-privilege run
waits for the `STEWARD` account.

Signing in over plain HTTP straight to port 8443 cannot work, by design: the session
cookie is `Secure`, so the browser does not keep it. The successful sign-in path is
tested through nginx proxy manager over HTTPS, which is also the real deployment.

## Least privilege: the pool as STEWARD (2026-10-10)

The user created the service account `STEWARD` `[362,2]`, with authorized and default
privileges IMPERSONATE, TMPMBX and NETMBX, batch access only, and flags RESTRICTED and
DISCTLY. The build is staged in `SYS$SYSDEVICE:[STEWARD]`
(`[.BIN]`, `[.COM]`, `[.RUN]` protected `(S:RWE,O:RWED,G,W)`), and the pool is started
with `SUBMIT/USER=STEWARD`.

- `STEWARD_POOL STATUS`: both processes are user STEWARD with `DETACH,TMPMBX,NETMBX`
  only.
- Through the test lighttpd: health is 200. A wrong password for `STEWARD_TEST` gives a
  generic 401 and an intrusion record `<client>::STEWARD`. `SESSIONS.DAT` and
  `AUDIT.LOG` are created by the service.
- ~~So `$ACM` sign-in and personas need only IMPERSONATE~~ **Wrong, corrected the same
  day (see "Persona creation needs UAF access" below).** These checks covered `$ACM`
  and a *failed* sign-in, which never creates a persona.

Findings:
- **With only IMPERSONATE, `$ACM` hides the reason for a failure.** The audit record
  says `%ACME-E-AUTHFAILURE`; with every privilege it was `%LOGIN-F-INVPWD`. The
  reason is still in the OpenVMS security audit; Steward's log records only that a
  sign-in failed. That is accepted: Steward never tells the client the reason anyway.
- **A RESTRICTED account with no login procedure cannot log in at all, batch
  included** (`%DCL-E-NOCMDPROC, error opening captive command procedure - access
  denied`). Fixed with a do-nothing `LOGIN.COM` the account can read but not change
  `(S:RWE,O:RE,G,W)`. The kit must install one.
- **Files the service created took the account's default protection, including group
  read** (`RWED,RWED,RE,`). `[.RUN]` already denied the group, but the pool now sets
  `(S:RWED,O:RWED,G,W)` as the process default so the files do not depend on the
  directory, and the existing ones were tightened.
- AUTHORIZE pre-expires a new account's password. `$GETUAI` shows the password date as
  `%XFFFFFFFFFFFFFFFF`, which is the marker `expired_now()` treats as expired: the
  first check of that logic against a real record.

## Authorized-but-not-default privileges (`probe_setprv`, 2026-10-10)

The user gave `STEWARD_TEST` GRPPRV as authorized only (default privileges unchanged).
Under its persona:

| | current privileges | authorized |
|---|---|---|
| just assumed | TMPMBX, NETMBX (`%X..00108000`) | + GRPPRV (`%X0000000400108000`) |
| `$SETPRV GRPPRV` | **NORMAL; GRPPRV now enabled** | |
| `$SETPRV SYSPRV` | NOTALLPRIV; nothing changes | |

A persona starts with the user's default privileges and can enable any privilege
the user is authorized for, as `SET PROCESS/PRIVILEGE` does, but nothing beyond.
This closes the last open probe question. How Steward should offer it is proposed
as D9.

## Through nginx proxy manager (2026-10-10)

The user published the test lighttpd as `x86.issinoho.com` in NPM. NPM connects to
lighttpd from its LAN address, which was found in lighttpd's access log and set as
`STEWARD_TRUSTED_PROXIES` in `[STEWARD.RUN]STEWARD_SETTINGS.COM`.

- Over HTTPS the page and API are served through NPM (openresty) with Steward's
  headers.
- A same-origin sign-in POST with the wrong password, with Origin
  `https://x86.issinoho.com`, got a 401, not a 403. So the scheme reconstructed from
  `X-Forwarded-Proto` matched the browser's Origin. The audit and intrusion records
  name the client NPM saw, not NPM itself.
- From inside the LAN through the public name, the client appears as the router
  (hairpin NAT). Internet clients, and LAN clients whose DNS points the name straight
  at NPM, appear as themselves.

Raised with the user: NPM also serves the host over plain HTTP with no redirect
(turn on Force SSL and HSTS), and the name resolves to the public address (limit it
with an NPM access list until the Phase 5 external review).

## Persona creation needs UAF access, not just IMPERSONATE (2026-10-10)

The user's first real sign-in through NPM (correct password) failed with
`%SYSTEM-F-NOGRPPRV, operation requires GRPPRV privilege`. `$ACM` had accepted the
password; the failure came at the first `$PERSONA_CREATE`.

Reproduced with `probe_selfuai` submitted with `SUBMIT/USER=STEWARD` (privileges
DETACH, TMPMBX, NETMBX):

```
[natural] $GETUAI STEWARD_TEST     FAIL %SYSTEM-F-NOGRPPRV
$PERSONA_CREATE                    FAIL %SYSTEM-F-NOGRPPRV
```

`$PERSONA_CREATE` reads the user's UAF record and applies `$GETUAI`'s access rules:
the caller's own record is free; another member of its UIC group needs GRPPRV;
anyone else needs SYSPRV. `STEWARD` `[362,2]` and `STEWARD_TEST` `[362,1]` share
group 362, hence GRPPRV; any other user would need SYSPRV. **IMPERSONATE alone cannot
create a persona for anyone but the service itself.**

Why the earlier evidence missed it: every probe that created a persona ran from the
work account, which holds every privilege. The least-privilege check on the node
covered a *failed* sign-in only, and that never creates a persona. Lesson, now in
the review checklist: verify least privilege with the **success** path, run as the
real account.
