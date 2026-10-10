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
| 5 | Can a detached service check a password non-interactively with `SYS$ACM`, and does that apply DISUSER, expiry and intrusion detection? | Probe builds; needs a test password. | **open** |
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

## Probe 5: to run (needs you)

Use a test account whose password you are willing to type on the node, ideally a
dedicated one such as `STEWARD_TEST`. From the work directory's `[.PROBES]`:

```
$ define/process/nolog STEWARD_PROBE_PW "the-password"
$ mcr sys$disk:[]probe_acm STEWARD_TEST
$ deassign/process STEWARD_PROBE_PW
```

Then repeat it with a wrong password (and run `SHOW INTRUSION`), with the account
DISUSERed, and with the password pre-expired. Each run prints the ACMESB statuses for
the three forms (plain, network logon type, acquire credentials).
