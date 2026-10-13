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

## An SSH connection in accounting, and its log (2026-10-11)

VSI OpenSSH V9.9-2C on the x86 node. Each connection is a NETWORK process under
SSH$SSH, whose remote full name is the client's *host name* (not its address). A
command (`ssh host cmd`) runs as a SUBPROCESS under SSH$SSH, with a SUBPROCESS under the
user (in lower case) beneath that. A shell or SFTP session is a NETWORK process under
the user, with the client's *address* as remote full name. The per-connection log
`x86vms_<host>_<pid>.log` is named after the SSH$SSH process's PID, which joins the
two exactly. Connections follow each other within the second. A session process that
merely *starts* inside a connection's lifetime may belong to the next one, so the
match is on the connection that contains it entirely (start and end), as observed with
consecutive `tools/vms.sh` calls. The logs are purged quickly: about 20 were on disk at
one point, so older connections keep their user and address (from accounting) but
lose the sign-in method.

## Accounting writes a pseudo-terminal's unit in binary (2026-10-11)

A failed SSH password gave an ACR$K_LOGFAIL record with terminal `"FTA" 45 02`, which
is FTA581: (0x0245), and username `<login>` with the name tried as remote ID. The
audit journal recorded the same attempt as LOGFAIL *LOCAL* with terminal `_FTA581:`
and the client address as remote node. The OpenSSH log has `Failed password for
steward_test from <client> port ... ssh2`. Steward shows these three as one failure.

## ACCOUNTNG.DAT and Steward's log cannot be COPYed while in use (2026-10-11)

`COPY` of Steward's audit log failed with `%RMS-E-FLK`: the pool holds it open for
writing. `CONVERT/SHARE` copies it. Steward itself reads both with SHRPUT|SHRUPD|UPI and
no record locks.

## Without access, ACCOUNTNG gives FNF, not PRV (2026-10-11)

As STEWARD_TEST (no privileges), opening `ACCOUNTNG` (default `SYS$MANAGER:.DAT`)
returned `%RMS-E-FNF` where the journal and the SSH logs returned `%RMS-E-PRV`.
SYS$MANAGER is a search list, which is the likely cause. The same file opened at once
with SYSPRV on. Access history passes OpenVMS's status through as it is, so the
accounting source may say "file not found" for a viewer who lacks the privilege.

## LIB$WAIT takes VAX F_floating unless told otherwise (2026-10-11)

`lib$wait(&seconds)` with a C `float` waited almost nothing on x86. VSI C passes IEEE
S_floating there, which LIB$WAIT reads as F_floating. Pass the float type:
`lib$wait(&seconds, 0, &four)`, where 4 is LIB$K_IEEE_S. A probe's "10-second timeout"
was really about 0.1 s, and for a while it made a working process look hung.

## A mailbox read larger than the mailbox's maximum message fails at once (2026-10-11)

`IO$_READVBLK` with a buffer longer than the mailbox's `maxmsg` returns
`%SYSTEM-F-MBTOOSML` without reading. The writer (here DCL's `SHOW LOGICAL/OUTPUT=` to the
mailbox) then waits for ever for a reader, in LEF. Read at most `maxmsg` bytes.

## Creating processes under a persona (2026-10-11, probe_lnm)

Each case was checked in accounting, which shows the process's username, UIC and
privileges.
- **`LIB$SPAWN` under an assumed persona** returns `%SYSTEM-F-NOPRIV`. This happens with
  any output, and with the copying of symbols, logical names and keypad state turned
  off. As the natural persona, the same call works.
- **A `$CREPRC` subprocess** of LOGINOUT runs as the persona (UIC and privileges), but
  waits in LEF with no image, presumably for the context LIB$SPAWN would send.
- **A `$CREPRC` detached process** of LOGINOUT (`PRC$M_DETACH`, which needs
  IMPERSONATE) runs as the persona.
  - With a **mailbox** as its input, LOGINOUT takes the mailbox for a terminal and
    waits.
  - With a **mailbox** as its output, DCL fails with `%RMS-F-DEV`.
  - With a **procedure file** as input and NLA0: as output, it runs, after SYLOGIN and
    the user's LOGIN.COM, as any detached process does.

**`SHOW LOGICAL/STRUCTURE` nests tables by parent, not by directory** (Phase 7,
2026-10-13). Under `(LNM$SYSTEM_DIRECTORY)` each table is indented under its parent
table, the one its quota comes from: `JBC$QUEUE_TO_QMAN` under `LNM$SYSTEM_TABLE`,
`LNM$SYSCLUSTER_TABLE` under `LNM$CLUSTER_TABLE`. Every one of them is still a name in
LNM$SYSTEM_DIRECTORY, so `GET logicals/tables` lists them all, unnested. The directory
does not appear as its own child in /STRUCTURE, but `SHOW LOGICAL/FULL/TABLE=
LNM$SYSTEM_DIRECTORY` lists it as one of its own names. Observed with
`tools/vms.sh x86 dcl "show logical/structure"` against the tables endpoint.
