# Phase 2: users and rights identifiers, read-only

Six read-only endpoints (docs/api.md) and four browser views: user list, user detail,
identifier list, identifier detail. Every request runs under the caller's persona
(D2), so OpenVMS decides what each user may read. Steward adds no access rules of
its own and hides nothing OpenVMS shows (D10).

## How the data is read

| What | How | Needs, as OpenVMS enforces it |
|---|---|---|
| List users | RMS sequential read of SYSUAF by key 0 (username), shared, `RRL+NLK` so it never locks a record (PHASE0 #3). A cursor is a keyed `KGT` read. Each name then goes through `$GETUAI` | SYSUAF is `(S:RWED,O:RWED,G,W)`, so SYSPRV or READALL |
| One user | `$GETUAI`, one call with about 50 items | own record: nothing; same UIC group: GRPPRV; anyone: SYSPRV |
| Identifiers held | `$ASCTOID` on the username gives its UIC identifier, then `$FIND_HELD` | nothing (see below) |
| List identifiers | `$IDTOASC` wildcard walk, sorted by name in Steward, as AUTHORIZE sorts | nothing |
| One identifier | `$ASCTOID` | nothing |
| Holders | `$FIND_HOLDER`, then `$IDTOASC` on each holder's UIC | nothing |

Flags and identifier attributes are mapped bit by bit from UAIDEF's and KGBDEF's own
masks, which were read from the node's `SYS$STARLET_C.TLB`, never from memory. Two
names differ from what you might guess:
- DISUSER is `UAI$M_DISACNT`.
- AUTHORIZE's DISMAIL is `UAI$M_NOMAIL`, and its DISNEWMAIL is `UAI$M_DISMAIL`.

The API uses AUTHORIZE's names, the ones a system manager types after `/FLAGS=`.

## Findings on the x86 node (2026-10-10)

Run with `tests/vms/api_probe`, which plants a session for a named user in a scratch
store and sends one request through the real dispatcher and platform. The request
runs under that user's persona, exactly as a signed-in request does.

1. **The rights database is readable by everyone.** RIGHTSLIST.DAT is
   `(S:RWED,O:RWED,G,W)`, yet an unprivileged persona (STEWARD_TEST, TMPMBX+NETMBX)
   listed all 31 general identifiers with `$IDTOASC`. It also read the holders of
   APACHE$READ with `$FIND_HOLDER`, and APACHE$WWW's held identifiers with
   `$FIND_HELD`. The services read the database in executive mode, so the file
   protection does not apply. The first version fetched a user's UIC with `$GETUAI`
   before calling `$FIND_HELD`, which made Steward stricter than OpenVMS. It now takes
   the UIC from the UIC identifier, so `$FIND_HELD` alone decides.
2. **`$GETUAI` reports a missing user before it checks privilege.** As STEWARD_TEST,
   `users/SYSTEM` gives `%SYSTEM-F-NOSYSPRV` and `users/NOSUCHUSER` gives
   `%RMS-E-RNF`. A signed-in user can therefore tell whether a username exists.
   Unprivileged users already can at a terminal (MAIL, the rights database in finding
   1), so Steward passes on what OpenVMS says (D10). Before sign-in, nothing changes:
   every failure still looks the same (Phase 1).
3. **GRPPRV works as documented.** With GRPPRV switched on (D9), STEWARD_TEST read
   STEWARD's record (both in group 362), and was still refused SYSTEM's
   (`NOSYSPRV`) and the user list (`RMS-E-PRV`).
4. **UAF times are local time.** EASTERN's password date came out as 13:05 UTC, where
   AUTHORIZE shows 13:05 and the node runs BST (`SYS$TIMEZONE_DIFFERENTIAL` 3600).
   `decc$fix_time` did not help: with no `TZ` and no C RTL time zone rules, it
   returned the local time unchanged. Steward now subtracts the system's current
   offset (local clock minus `time()`, rounded to 15 minutes), so the times match
   AUTHORIZE. A date from the other side of a daylight-saving change is an hour out,
   as it is everywhere on OpenVMS, which keeps only the current differential.
5. **The VSI C RTL lowercases unquoted `argv`.** The probe's `GRPPRV` argument
   arrived as `grpprv`. This was a test-tool bug, not a product one. It is recorded
   because it looked like a privilege failure.

## Compared with AUTHORIZE (exit criterion)

`AUTHORIZE SHOW` for STEWARD, STEWARD_TEST, APACHE$WWW, EASTERN and SYSTEM against
`users/{u}`, field by field. Every one matched:
- owner, account, UIC, CLI and tables, default device and directory, LGICMD;
- flags: DisCtlY Restricted; LockPwd DisNewMail DisMail DisReport; Restricted GenPwd;
- primary and secondary days, and the access-hour grids for all five kinds of login;
- expiration, password lifetime (60 and 9938 days), minimum length, login failures
  (830, 15), pre-expired, password change date and last login (after finding 4);
- all 21 quotas and limits;
- authorized and default privileges.

APACHE$WWW's identifiers (APACHE$APR_ALL, APACHE$READ, APACHE$EXECUTE, with values)
match AUTHORIZE's list. The identifier list (`type=all`, as STEWARD_TEST) was compared
by script with `SHOW/IDENTIFIER *`. All 80 identifiers, general and UIC, match on
name, value (AUTHORIZE's zero-padded octal UICs normalised) and attributes, and they
come in the same order. APACHE$READ's holders match.

A non-privileged sign-in gets a 403 with the OpenVMS message for the user list and
for others' records, and its own record in full (exit criterion: "403 or reduced
data").

## Phase exit (2026-10-10, x86 node, through nginx proxy manager over HTTPS)

The user signed in as STEWARD_TEST and confirmed each check in the browser:
- the user list was refused with `%RMS-E-PRV`, and the page linked to the user's
  own record;
- that record matched `AUTHORIZE SHOW STEWARD_TEST`, with times in local clock time;
- with GRPPRV switched on, STEWARD's record (same group) opened;
- APACHE$READ showed its holder, APACHE$WWW.

D10 was approved as built. Gate: the threat model is updated (security.md, "Phase 2
additions"). The review of the Phase 2 code against the checklist found three
issues, each fixed with a test (security.md audit record). `make audit` and CI are
clean. On VMS the pool runs as STEWARD with current privileges
`DETACH,TMPMBX,NETMBX`, and no LINK reported a warning.

**Phase 2 closed on 2026-10-10 with the user's approval.**
