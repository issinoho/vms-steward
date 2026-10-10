# Phase 0: platform probes

Run on `<x86-host>`: OpenVMS E9.2-4 x86-64 (QEMU), VSI C V7.7-003, OpenSSL 3.0.21
(`SSL3$LIBCRYPTO_SHR32`). Probes are in `probes/`. They are built and the read-only ones
run by `@RUN_PROBES`, and `probe_persona`/`probe_acm` are run by hand. Raw output stays in
the git-ignored `cache/`, because it lists the node's accounts.

All runs were made from the work account, which holds every privilege, so "needs
privilege X" below is not yet established. Phase 1's service account (IMPERSONATE only)
settles it.

| # | Question | Answer | Status |
|---|---|---|---|
| 1 | Do VSI C, 32-bit pointers and SSL3 give us RNG, SHA-256 and HMAC? | Yes. `RAND_bytes`, plus SHA-256 and HMAC-SHA256 matching the FIPS 180-2 and RFC 4231 vectors. | **answered** |
| 2 | Can the rights database be enumerated? | Yes. `$IDTOASC` with id -1 walks every identifier and ends with NOSUCHID, giving general (bit 31) and UIC identifiers. `$FIND_HELD` and `$ASCTOID`/`$FIND_HOLDER` work too. | **answered** |
| 3 | Can SYSUAF be enumerated? | Yes. An RMS sequential `$GET` with RRL+NLK (it never takes a record lock), with the username at offset 4. `$GETUAI` agreed on every record (43 records, 0 failures, 0.25 s CPU including the `$GETUAI` calls). | **answered** |
| 4 | Does a persona make the OS check the caller's rights (D2)? | **Yes.** Under an unprivileged persona (TMPMBX+NETMBX), `$GETUAI SYSTEM` failed with NOSYSPRV and `$OPEN SYSUAF` with RMS-E-PRV. After reverting to the natural persona both succeeded, and `$GETJPI` showed the username and privileges switch and switch back. Under a privileged persona both succeeded. | **answered** |
| 5 | Can a detached service check a password non-interactively with `SYS$ACM`, and does that apply DISUSER, expiry and intrusion detection? | **Mostly.** A non-dialogue `$ACMW` (no context) authenticates. A right password succeeds in all three forms, and `ACME$M_ACQUIRE_CREDENTIALS` returns a persona handle. DISUSER is refused (AUTHFAILURE / LOGIN-F-DISUSER), and so is a wrong password (AUTHFAILURE / LOGIN-F-INVPWD). Intrusion detection counts the failures. **But a pre-expired password is accepted**, and **the intrusion record names the service's process, not the client** (see below). | **answered, with two gaps** |
| 6 | FastCGI socket and pool | Settled by vms-lighttpd: `PHP_POOL.COM` runs detached LOGINOUT processes on `127.0.0.1:<base+n>` in a restart loop, with a stop file. We copy that shape. | **answered (prior art)** |

## Findings that shape Phase 1

- **Header quirks (VSI C V7.7, default starlet):** there is no `<impdef.h>` (use flags 0
  for `$PERSONA_ASSUME`). `<acmedef.h>` uses `utcblk` without including
  `<utcblkdef.h>`, so include that first. `acmesb$l_acme_id` is a struct (`acmeid`).
  `ISS$C_ID_NATURAL` (1) comes from `<issdef.h>`.
- **Username case:** `$PERSONA_CREATE` accepted a lowercase username, and `$GETJPI`
  then reported it in lowercase. The service must upcase and validate usernames itself
  before creating a persona, never pass them through as given.
- **A persona gets the user's default privileges.** The work account's authorized and
  default sets are identical, so we can't yet tell whether a persona can enable an
  authorized-but-not-default privilege (as `SET PROCESS/PRIVILEGE` does). This
  matters for admins whose SYSPRV is authorized only, so it gets a probe in Phase 1.
- **VSI WebUI is installed on this node** (there is a `WEBUI_WRITE` identifier). Our
  identifiers, logicals and files must use `STEWARD` names and never touch WebUI's.
- **SYSUAF reads are cheap:** a full pass is well under a second for a small UAF.
  Listing users can therefore read the file per request at first, with paging and a cache
  only if a large UAF needs them.

## Probe 5: SYS$ACM (run by the user, 2026-10-10)

Run against the dedicated unprivileged account `STEWARD_TEST` (TMPMBX, NETMBX), from the
work account, in this order: right password, DISUSER, pre-expired, wrong password.
`STEWARD_TEST` stays for Phase 1 as the unprivileged test login.

| Case | All three forms (plain, network logon type, acquire credentials) |
|---|---|
| right password | ACME-S-NORMAL; form C returned persona handle 2 |
| DISUSER | ACME-E-AUTHFAILURE, secondary LOGIN-F-DISUSER |
| pre-expired password | **ACME-S-NORMAL**: accepted, no warning in the ACMESB |
| wrong password | ACME-E-AUTHFAILURE, secondary LOGIN-F-INVPWD |

`SHOW INTRUSION` after the wrong-password run: `NETWORK SUSPECT 3 ... X86VMS::IAIN`.

### Two gaps Phase 1 must close (each gets a probe first)

1. **An expired password is not refused in non-dialogue mode.** An interactive login
   would force a change, but here nothing signals it. Before issuing a session, Steward
   must check expiry itself (`UAI$_FLAGS` PWD_EXPIRED/PWD2_EXPIRED, and `UAI$_PWD_DATE`
   against `UAI$_PWD_LIFETIME`), or find the ACME output item that reports it. It must
   then refuse with "password expired" and offer a change-password flow
   (`ACME$_FC_CHANGE_PASSWORD`). This is now part of D2.
2. **Intrusion records name the service, not the browser.** The source is the service's
   own process (`node::user`). If nothing changes, one attacker's failures make every web
   login a suspect, and when the record turns INTRUDER, breakin evasion would block all
   web logins: a denial of service, with the attacker's address never recorded. Phase 1
   must probe the `ACME$_REMOTE_HOST_ADDRESS`/`ACME$_REMOTE_HOST_NAME` items with the
   client IP from lighttpd (`REMOTE_ADDR`), so each client gets its own intrusion record.
   Until that works, Steward also rate-limits failed logins per client IP itself.

The runs were made with the work account (all privileges). That ACM needs only
IMPERSONATE is still to be shown with the Phase 1 service account.

## Exit

Phase 0 closed 2026-10-10. Every question is answered, and the two ACM gaps above carry
into Phase 1 as its first probes.
