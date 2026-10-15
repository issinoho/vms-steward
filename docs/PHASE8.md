# Phase 8: processes

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

## Exit (8a)

- The list and one process match `SHOW SYSTEM` and `SHOW PROCESS/ALL`, for STEWARD_TEST
  (its own only) and STEWARD_ADM with GROUP and with WORLD.
- A process the viewer may not see is refused as OpenVMS refuses it.
- Steward's serving process is never shown under the viewer's name.
- Browser checks (the user's); the security gate (security.md).
