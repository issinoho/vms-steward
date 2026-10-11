# Notes

Platform findings, each with how it was observed. Phase exits are recorded here too.

## VSI C does not resolve `../` in `#include "..."` (2026-10-10)

`#include "../core/st_http.h"` failed with `%CC-F-NOINCLFILEF` on VSI C V7.7-003 x86-64,
from `[.src.svc]`. Includes in the same directory worked. All project includes are now
bare names (`#include "st_http.h"`), with the directories given as `-I` in the Makefile
and `/INCLUDE_DIRECTORY` in `build_vms.com`. Keep both lists in step.

## `RUN/DETACHED LOGINOUT` without `/AUTHORIZE` ignores the UAF privileges (2026-10-10)

After SYSPRV was added to STEWARD's authorized privileges, the pool (started by
`SUBMIT/USER=STEWARD`) still showed `F$GETJPI(pid,"AUTHPRIV")` =
`DETACH,TMPMBX,NETMBX`. Without `/AUTHORIZE`, LOGINOUT gives the detached process
the creator's privileges, so the batch job's *current* (default) set became the
child's *authorized* set. With `/AUTHORIZE` the process logs in properly:
AUTHPRIV = `DETACH,TMPMBX,NETMBX,SYSPRV`, CURPRIV = `DETACH,TMPMBX,NETMBX`, and
the quotas come from the UAF, so the pool no longer sets them. A RESTRICTED
account needs a LOGIN.COM for this, which `[STEWARD]` has.

## The rights database is world-readable through system services (2026-10-10)

RIGHTSLIST.DAT is `(S:RWED,O:RWED,G,W)`, but an unprivileged persona read every
identifier (`$IDTOASC` wildcard), the holders of one (`$FIND_HOLDER`), and another
user's holdings (`$FIND_HELD`). The services read the file in executive mode.
SYSUAF is different: RMS refuses to open it without SYSPRV or READALL. Details are
in PHASE2.md.

## UAF times are local, and the C RTL has no time zone rules here (2026-10-10)

`$GETUAI` dates (password change, last login, expiration) are local system time. With
`SYS$TIMEZONE_DIFFERENTIAL` 3600 (BST), they read an hour late when taken as UTC.
`decc$fix_time` returned them unchanged, because `TZ` is not defined. Steward subtracts
the current offset instead (PHASE2.md, finding 4).

## The VSI C RTL lowercases unquoted `argv` (2026-10-10)

`api_probe STEWARD_TEST GRPPRV ...` arrived with `argv[2]` = `grpprv`. DCL upper-cases
unquoted parameters, and the C RTL then lowercases them unless
`DECC$ARGV_PARSE_STYLE` is enabled. Command-line tools must compare case-insensitively,
or the user must quote the argument.

## UAIDEF names (2026-10-10)

Read from `SYS$LIBRARY:SYS$STARLET_C.TLB`, not guessed:
- DISUSER is `UAI$M_DISACNT`.
- AUTHORIZE's DISMAIL is `UAI$M_NOMAIL`, and DISNEWMAIL is `UAI$M_DISMAIL`.
- DISWELCOME is `UAI$M_DISWELCOM`.
- Bit 20 is `UAI$M_DEFCLSVAL`.

## No `struct timeval` under /STANDARD=C99 (2026-10-11)

`gettimeofday` with `struct timeval` failed to compile (`%CC-E-INCOMPNOLINK`) in VSI C
with `/STANDARD=C99`. The VMS platform takes milliseconds from `$GETTIM` instead
(local time, less the current UTC offset), and the stub uses `time()`.

## `$GETSYI` and `$GETRMI` items want 8-byte buffers here (2026-10-11)

With 4-byte buffers, `RMI$_FRLIST`, `RMI$_MODLIST` and the page-file items came back
as 0 on the x86 node. With 8, as vms-fastfetch gives every item, they match
`SHOW MEMORY`. The exceptions are `RMI$_CUR`, `COM` and `COMO`, which need exactly 4
(fastfetch D15).
