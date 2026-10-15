# Phase 8: processes

8a (read-only) and 8b (stopping) closed 2026-10-15. Phase 8 is closed.

Read-only first (8a), then stopping a process (8b), as for users and logical names.
Design: DECISIONS D16.

## How processes are read (probe, 2026-10-15)

`$GETJPI` with a wildcard PID walks the system; under a persona, OpenVMS skips each
process the persona may not see with NOPRIV and the walk goes on. So the list is
whatever the viewer would see at a terminal, with no helper process (unlike logical
names, D14). `probes/probe_jpi.c`, from my work process (which holds every
privilege), under each persona:

| Persona, switched on | Walk | One PID: a pool process | One PID that does not exist |
|---|---|---|---|
| STEWARD_TEST, none | only its own process | NOPRIV | NONEXPR |
| STEWARD_TEST, GRPPRV | only its own | NOPRIV | |
| STEWARD_ADM, SYSPRV | only its own | NOPRIV | |
| STEWARD_ADM, GROUP | group 362: its own and Steward's two pool processes | OK | |
| STEWARD_ADM, WORLD | all 42 processes, 0.01 s CPU | OK | |

For it the user agreed to authorize GROUP and WORLD for STEWARD_ADM (it now has
GROUP, NETMBX, SYSNAM, SYSPRV, TMPMBX, WORLD authorized).

Found:
- **The asking process is the persona.** `$GETJPI` on the process running the request
  reports the persona's username and UIC. In Steward that is the pool process, which
  would appear in every viewer's list under their own name. It is left out.
- **NOPRIV and NONEXPR differ**, as at a terminal (`SHOW PROCESS/ID=`): an existing
  process the viewer may not see is NOPRIV, a PID that does not exist is NONEXPR.
  Steward answers as OpenVMS does (403 and 404): no more than the terminal reveals.
- **On x86 the service account shares UIC group 362 with the test accounts**, so GROUP
  in that group shows (and would let one stop) Steward's pool. README.VMS already
  advises a group of its own.

## Scope

**Read-only (8a):**
- `GET api/v1/processes?filter=`: the processes the viewer may see, as `SHOW SYSTEM`
  lists them: PID, process name, username, UIC, state, priority, mode (interactive,
  batch, network, detached, subprocess), terminal, image, CPU time, I/O counts and
  page faults. Steward's own serving process left out.
- `GET api/v1/processes/{pid}`: one process, as `SHOW PROCESS/ALL` shows it: the above,
  plus login time, owner and master PID, subprocesses, working set and page file use,
  current and authorized privileges, rights, and each quota with what is left.
- The view: a list with a filter, and a process page.

**Stopping (8b, after 8a's exit; the user's choice, 2026-10-15):** `STOP/ID` (`$DELPRC`)
under the persona, OpenVMS deciding (GROUP or WORLD for others' processes). Confirmed
first, audited. Steward refuses to stop the service account's processes, its pool.
Suspend, resume and priority were not chosen.

**Folded in from the Phase 7 review:** a plain-text logical-name filter over 61
characters is refused rather than cut, and the tables list says when it was cut
short (`truncated`).

## Built (8a, 2026-10-15)

- **Core:** `src/core/st_proc.{h,c}`: PIDs in OpenVMS's form, state names and kinds from
  constants taken from the node's STATEDEF and JPIDEF.
- **Platform:** `st_plat_proc_enum` (wildcard `$GETJPI`, NOPRIV and SUSPENDED skipped,
  the serving process left out) and `st_plat_proc_get` (one PID, with privileges,
  rights and quotas). The stub has x86's shape of processes.
- **API:** the two endpoints (api.md). **View:** `www/js/processes.js`.
- **Tests:** 308 unit checks (Linux and x86); `make ui-test` 14 ok; on x86
  `tests/vms/phase8_live.py` 10 ok, 0 failed: with WORLD the same 35 processes as
  `F$PID`/`F$GETJPI` (ssh and work-account processes left out as transient), each
  with DCL's name, username, UIC and base priority; GROUP shows only group 362;
  STEWARD_TEST sees none (its only process is the serving one); NOPRIV and NONEXPR
  as `SHOW PROCESS/ID`.
- From the Phase 7 review: an over-long plain logical-name filter refused, the tables
  list's `truncated`.

Kit T0.7-0 (2026-10-15), built by `tools/kit.sh x86` (308 native checks), SHA-256
`1478f4a22fd41c3044c70881009058910bd4cf0e2a0eda6b05d7518264ce23c2`, for the browser
checks.

## Exit (8a)

- The list and one process match `SHOW SYSTEM` and `SHOW PROCESS/ALL`, for STEWARD_TEST
  (its own only) and STEWARD_ADM with GROUP and with WORLD.
- A process the viewer may not see is refused as OpenVMS refuses it.
- Steward's serving process is never shown under the viewer's name.
- Browser checks (the user's); the security gate (security.md).

## 8a closed (2026-10-15)

On the installed kit T0.7-0, the user's browser checks:

| Criterion | Shown by | State |
|---|---|---|
| List and one process match `SHOW SYSTEM` / `SHOW PROCESS/ALL` | `phase8_live.py` 10 ok; the user compared a process page with `SHOW PROCESS/ALL` | done |
| STEWARD_TEST sees only its own | browser: nothing (its only process was the serving one) | done |
| STEWARD_ADM with GROUP, with WORLD | browser: GROUP showed `STEWARD_19301` alone (`STEWARD_19300` was serving the request, so not listed); WORLD 38 processes | done |
| A process the viewer may not see is refused as OpenVMS refuses it | browser: by PID, `%SYSTEM-F-NOPRIV` | done |
| The serving process never shown under the viewer's name | live test and the GROUP check above | done |
| Security gate | security.md Phase 8 section and invariant | done; review of the 8a files with 8b's |

Seen in the check: which pool process is missing from a GROUP or WORLD list depends on
which one answered. Correct, but worth saying on the page: a line under the list, in 8b.

## 8b: stopping a process (started 2026-10-15)

**Probe** (`probes/probe_delprc.c`), against three batch jobs submitted as STEWARD_TEST
for the purpose (each waiting five minutes):

| Persona, switched on | Target | `$DELPRC` |
|---|---|---|
| STEWARD_ADM `[362,3]`, none | STEWARD_TEST's job | NOPRIV (my process holds every privilege) |
| STEWARD_ADM, GROUP | the same job | NORMAL; the job gone a moment later |
| STEWARD_TEST, none | its own job | NORMAL; gone |
| STEWARD_ADM, GROUP | a PID that does not exist | NONEXPR |

The third job was deleted by hand (`DELETE/ENTRY`), and the procedure removed.

**Design** (D16): `DELETE api/v1/processes/{pid}`, `$DELPRC` under the persona, 202;
the service account's processes refused (409); audited; the browser asks for the
process name to be typed first. Also from 8a's check: a line under the list saying
the serving process is not listed.

**Built (2026-10-15):** `DELETE api/v1/processes/{pid}`, the Stop dialog, and the
review's fixes (Steward's image refused too; FFFFFFFF refused). Tests: 326 unit, 53
API, 17 UI; on x86 `phase8b_live.py` 10 ok, 0 failed. Its first run stopped the real
`STEWARD_19300` (the test tool's service account is the work account; NOTES.md):
restarted at once, and the test no longer names a pool process.

Kit T0.7-1, built by `tools/kit.sh x86` (326 native checks), SHA-256
`0dca180314ea5b4137598aad2d233bda249bd83f47af8b17d72ac20e3c8d6214`.

**Exit (8b):**
- A stop matches STOP/ID: what OpenVMS refuses is refused (NOPRIV), what it allows
  happens, for STEWARD_TEST (its own) and STEWARD_ADM with GROUP.
- Steward's pool can never be stopped through Steward.
- Every stop is audited.
- Browser checks (the user's); the security gate, with a review of 8a and 8b.

## 8b closed (2026-10-15)

On the installed kit T0.7-2 (SHA-256
`143a769ce5b0f212306f09311225afc584445f50ca8c64a95c9f802d709405c5`):

| Criterion | Shown by | State |
|---|---|---|
| A stop matches STOP/ID | `phase8b_live.py` 11 ok; browser: BATCH_249 stopped by STEWARD_ADM with GROUP | done |
| What OpenVMS refuses is refused | NOPRIV without GROUP (live) | done |
| Steward's pool never stopped through Steward | browser: `STEWARD_19301` refused; live: a busy worker (persona held) refused by its image | done |
| System processes never stopped through Steward (added after OPCOM was stopped in the first check) | browser: OPCOM shows no Stop; live: a job counted as system refused; OPCOM `"system": true` | done |
| Every stop audited | audit log on x86, the API suite | done |
| Security gate | security.md Phase 8 sections, invariants and four audit records; an independent review of 8a and 8b | done |

Found along the way: the live test stopped the real `STEWARD_19300` (the test tool's
service account), a busy pool worker reported under the requester's name, PID
`FFFFFFFF` as a wildcard, and OPCOM stopped in the browser check (restarted by the user
with `@SYS$SYSTEM:STARTUP OPCOM`; it now runs as username IAIN in `[1,4]` until the
next reboot or a restart from SYSTEM). STEWARD_ADM keeps GROUP and WORLD authorized
for testing.

