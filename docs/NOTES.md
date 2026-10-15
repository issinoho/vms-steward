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

**A global verb symbol takes over a command in a procedure, unless the procedure
sets `SET SYMBOL/SCOPE=NOGLOBAL`** (Phase 7 review, 2026-10-13). With `directory ==
"write sys$output ..."` defined, `$ directory nl:` in a procedure ran the symbol;
after `set symbol/scope=(nolocal,noglobal)` it ran the verb. A global `SHOW` symbol
never replaced the SHOW verb, scope or not. Observed with `probes/lnm_scope.com`.
The D14 helper runs after the viewer's LOGIN.COM, so it sets the scope first.

**A dead D14 helper costs about 2 s, a flooding one 30 s** (2026-10-13), timed on
the node with `F$CVTIME`: the termination message arrives at once and Steward reads
for a 2 s grace. Through `tools/vms.sh` the same call took 18 s once, so the live
test times these on the node.

**On x86, Steward is now served by the site's lighttpd** (2026-10-13). Until then it
ran behind a separate test lighttpd (`vms/lighttpd_test.com`, port 8443, as the work
account), which nothing restarts after a reboot: two reboots that afternoon left the
proxy with nothing on 8443, and it answered 502. At the user's request,
`LIGHTTPD.CONF;7` adds the include README.VMS describes, and STEWARD_GATEWAY.CONF is
now owned by LIGHTTPD: STEWARD$CONFIGURE had made it the work account's, for the test
server, and LIGHTTPD (not a system UIC) could not have read the secret. `;6` is
kept to roll back. Checked: the board on 80, Steward's page and health through the
proxy, and 401 (not 403) for an API request without a session, so the gateway secret
arrives. The pool did not start at boot after the reboots: SYSTARTUP_VMS.COM calls
STEWARD$STARTUP, but STEWARD$CONFIG.COM said `steward_autostart == "NO"`
(STEWARD$CONFIGURE's default), so it only defined STEWARD$ROOT. The user installed
`STEWARD$CONFIG.COM;4` with YES (`;3` kept). Not yet seen across a reboot. If
STEWARD$CONFIGURE is run again: YES to autostart, LIGHTTPD for lighttpd's account.

**`$CRELNM` and `$DELLNM` without SYSNAM quietly use user mode** (Phase 7b, 2026-10-13).
Asked for supervisor or executive mode from user-mode code without SYSNAM, `$CRELNM`
succeeds at *user* mode: `SS$_SUPERSEDE` if a user-mode name was there, which it then
replaces. `$DELLNM` at executive mode deletes the user-mode name the same way. With
SYSNAM switched on, each mode gets its own name. Steward checks SYSNAM itself before
either call for an inner mode. Observed with `probes/probe_crelnm.c` under STEWARD_ADM's
persona in LNM$SYSTEM_TABLE, with SYSPRV and then with SYSNAM.

**Which privilege opens which table, under a persona** (same probe). The persona's
privileges are what count: my work process holds every privilege, yet STEWARD_TEST's
persona gets NOPRIV for its own group table. Then:
- **Group table** (`(RWCD,R,R,)`, owner `[362,*]`): GRPPRV or SYSPRV opens it, as
  system access to the table. SYSNAM does not.
- **System table:** SYSPRV opens it through its protection, but only at user mode
  (above). SYSNAM gives the real modes.
- **LNM$GROUP** under the persona still names the *process's* group table
  (`LNM$GROUP_000200` here, not STEWARD_TEST's 000362): it is a name in the process
  directory, set at login. Steward names the viewer's group table explicitly.

**Deassigning at a mode also removes the name at every outer mode** (same day). With a
name at user, supervisor and executive mode in the system table, `$DELLNM` at
executive mode removed all three. DCL does the same: `DEASSIGN/SYSTEM/SUPERVISOR_MODE`
removed the supervisor and user names and left the executive one. And `SHOW
LOGICAL/FULL` showed only the user-mode one of the three: it lists a name's outermost
mode only. Observed with `tools/vms.sh x86 dcl`, defining `STEWARD_PROBE_7B` at each
mode and deassigning (the user agreed to the name; nothing was left).

**Defining a name NO_ALIAS deletes it at every outer mode** (Phase 7b, 2026-10-13).
With `STEWARD_PROBE_7B` at user and executive mode in the system table, replacing the
executive-mode one with `LNM$M_NO_ALIAS` left only the executive-mode name:
`$CRELNM` removed the user-mode one without a word. It answers `SS$_SUPERSEDE`
even when the name was new at its own mode and only the outer one went (found by
the Phase 7b review, confirmed by `phase7b_live.py`), so Steward decides "replaced"
from the modes it read before, not from that status. `SHOW LOGICAL/FULL` then shows `[exec,no_alias]`. Steward's answer to the
define lists the modes left, and the browser warns before sending `no_alias`. Observed
with `tests/vms/phase7b_live.py`, which first expected the user-mode name to survive.

**The helper process translates its procedure's path in its own context, outer modes
included** (Phase 7b, 2026-10-13). `$CREPRC` hands LOGINOUT the input file as a
string, and the new process (the viewer) translates it. A user- or supervisor-mode
name in the *viewer's* group table, or in the system table, took over from the
executive-mode system name: the helper ran the decoy procedure. A name in the
*service's* group table did not. So whoever could write a viewer's group table
(GRPNAM, or GRPPRV in that group) could have had that viewer's listings run their
procedure, as the viewer. Steward now resolves the path once at start-up, as the
service, with `NAM$M_NOCONCEAL` and the device's `DVI$_FULLDEVNAM` (`_DEV:`, never
translated), and gives the helper that. Afterwards the viewer-group decoys had no
effect. Observed with `probes/lnm_shadow.py` (STW_PROBE_ROOT, under
`[STEWARD_TEST.SHADOW]`), before and after the change.

**Browsers kept an old script module across a kit upgrade** (Phase 7b, 2026-10-15).
After 0.6.1 was installed and the page reloaded, the user's browser ran the new
`logicals.js` with the old `api.js`: the static files had no `Cache-Control`, so the
browser could reuse a module it had cached on its own (Last-Modified) heuristic.
"Modify executive…" then loaded the outermost (user) definition, and the audit log
shows user-mode defines. The server was serving the new `api.js` (checked with
curl). The static files now carry `Cache-Control: no-cache`, so the browser asks
again each time and gets a 304 if nothing changed. On x86 the user installed the edited
`STEWARD.CONF;4` (`;3` kept as the way back) and restarted lighttpd; afterwards
`x86.issinoho.com` sent `Cache-Control: no-cache` on `/js/api.js`, and the page, the
health check and the board on port 80 answered 200.

**Under a persona, $GETJPI reports the calling process as the persona** (Phase 8,
2026-10-15). A wildcard `$GETJPI` walk from my work process (every privilege) under
STEWARD_TEST's persona returned just one process, its own, with username
`steward_test` (in lower case, as the persona was created) and UIC `[362,1]`; every
other process came back NOPRIV, and the walk went on past each. With GROUP switched on
it showed group 362 (Steward's pool among them), with WORLD all 42 processes. One PID
the persona may not see is NOPRIV; one that does not exist is NONEXPR. Observed with
`probes/probe_jpi.c`.

**$DELPRC under a persona checks the persona, and returns before the process is gone**
(Phase 8b, 2026-10-15). Against batch jobs submitted as STEWARD_TEST (`[362,1]`) for the
purpose, from my all-privileged process: STEWARD_ADM's persona (`[362,3]`) got NOPRIV
with nothing switched on, and SS$_NORMAL with GROUP; STEWARD_TEST's own job could be
stopped with nothing switched on; a PID that does not exist gave NONEXPR. Straight
after an accepted `$DELPRC` the process still answered `$GETJPI`; a moment later it
was gone. Observed with `probes/probe_delprc.c`; the third job was deleted by hand.

**The test tool's "service account" is the work account: a live test stopped the real
pool** (Phase 8b, 2026-10-15). `tests/vms/api_probe` runs in my work account, and
`st_plat_init` takes the running process's username as the service account. So in the
probe, "Steward's own processes" meant the work account's, and the first
`phase8b_live.py` asked it to stop `STEWARD_19300` expecting a 409: it got 202, and the
real pool process was stopped. `STEWARD_19301` kept the site up; the pool was restarted
at once (`STEWARD$CONTROL RESTART`). The guard in the real pool, which runs as STEWARD,
was not at fault. Now `api_probe` can name the account (`API_PROBE_SERVICE_ACCOUNT`,
test-only, audit rule `service-account-test-only`), and the live test checks the
refusal on one of its own STEWARD_TEST jobs; it never names a pool process.
Also seen: `@BUILD_VMS TEST` did not relink `API_PROBE.EXE` after `st_plat_vms.c`
changed, so a run used the old probe; build from CLEAN before a live test that needs
a changed probe. And VSI C truncates external names over 31 characters
(`%CC-W-LONGEXTERN`): the setter's name was shortened.

**A process holding a persona is reported as the persona, to everyone; access still
follows its real owner** (Phase 8b, 2026-10-15, from the Phase 8 review). A detached
process of mine (`[200,101]`) held STEWARD_TEST's persona (`probes/probe_hold.c`).
From outside, `F$GETJPI` gave username `steward_test` and UIC `[362,1]`; its process
name and image were unchanged. STEWARD_TEST's own persona could not see it (NOPRIV),
nor STEWARD_ADM's with GROUP in 362; with WORLD it was listed, as `steward_test
[362,1]`. So a Steward pool worker busy with a request shows the requester's name,
and a guard by username alone would let anyone with WORLD (or GROUP in the service
account's real group) stop it. Steward now also refuses any process running its own
image. Observed with `probe_jpi` against the held PID.

**The browser check stopped OPCOM** (Phase 8b, 2026-10-15). STEWARD_ADM, with WORLD
switched on, opened OPCOM's page, pressed Stop and typed its name; OpenVMS allowed
`$DELPRC` (audit: `process-stop target="0000040B \"OPCOM\" SYSTEM" outcome="ok"`).
D16 refused only Steward's own processes then. The user chose to refuse system
processes (UIC group up to MAXSYSGROUP, read with `$GETSYI` at start-up: 8 on x86)
whatever the viewer holds. OPCOM is restarted with `@SYS$SYSTEM:STARTUP OPCOM`
(OPCOM is one of STARTUP.COM's requests), run by the user. Also seen: X86VMS_BATCH
ran three of four test jobs at once, other jobs taking the fourth slot; the live
test now waits for the last one.

**$GETQUI judges the persona; an empty queue answers NOSUCHJOB to a job walk**
(Phase 9, 2026-10-15). Under STEWARD_TEST's persona, from my all-privileged process,
`QUI$_DISPLAY_JOB` with `QUI$M_SEARCH_ALL_JOBS` returned other users' jobs with
`QUI$M_JOB_INACCESSIBLE` (%X8) and no name or username; with SYSPRV, everything.
STEWARD_ADM saw STEWARD_TEST's job in full (same UIC group; the queues give G:R). A
queue with no jobs answered `JBC$_NOSUCHJOB`, not `JBC$_NOMOREJOB`: a walk that skips
NOSUCHJOB and goes on never ends (the probe's first version, stopped by hand).
Observed with `probes/probe_qui.c`.

