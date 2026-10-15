# Phase 9: batch and print queues

9a (read-only) closed 2026-10-15; 9b (changes) next.

Read-only first (9a), then changes (9b), as for the earlier areas. Design: DECISIONS D17.

## How queues are read (probe, 2026-10-15)

`$GETQUI` asks the queue manager (JOB_CONTROL), another process; the probe shows it
judges each request by the persona, not by the asking process.
`probes/probe_qui.c` walked every queue and its jobs from my work process (every
privilege), as itself and under personas, with two held jobs in SYS$BATCH: entry 269
as STEWARD_TEST, entry 270 as me (both deleted afterwards).

| Asking as | Its own job | STEWARD_TEST's (`[362,1]`) | Mine (`[200,101]`) and other users' |
|---|---|---|---|
| my process | | shown | shown |
| STEWARD_TEST, none | shown | | entry and status only, `QUI$M_JOB_INACCESSIBLE` |
| STEWARD_ADM, none | | shown (same UIC group: the queues give G:R) | inaccessible |
| STEWARD_ADM, WORLD | | shown | inaccessible (world has only S) |
| STEWARD_ADM, SYSPRV | | shown | shown |

All four queues were listed to everyone. OPER is not authorized for STEWARD_ADM, so
it was not tried. Found:
- **Another's job is listed, but as inaccessible:** entry number and status, with
  `QUI$M_JOB_INACCESSIBLE` (%X8) set and no name or username, as `SHOW QUEUE/ALL`
  shows it at a terminal.
- **An empty queue answers JBC$_NOSUCHJOB to the job walk, not JBC$_NOMOREJOB.** The
  probe's first version treated it as "skip and go on", and looped until stopped by
  hand (my own process, `STOP/ID`).

## Scope

**Read-only (9a):**
- `GET api/v1/queues`: every queue, as `SHOW QUEUE` lists them: name, batch or output,
  generic or execution, status (started, stopped, paused, ...), node, job limit, and
  the counts of executing, pending, holding and timed jobs.
- `GET api/v1/queues/{name}`: one queue and its jobs, as `SHOW QUEUE/ALL/FULL`: each
  job's entry, name, username, status and submission time, or "inaccessible".
- `GET api/v1/jobs/{entry}`: one job as `SHOW ENTRY/FULL` shows it.
- The view: queues, a queue with its jobs, a job.

**Changes (9b, the user's choice, 2026-10-15):** hold and release a job, delete a job,
stop and start a queue, by `$SNDJBC` under the persona, OpenVMS deciding (the job's
owner, the queue's protection, OPER). Requeuing was not chosen. To be probed first:
that `$SNDJBC` judges the persona too. Stopping a queue Steward's own start-up uses
(SYS$BATCH and what it feeds) gets care, after OPCOM (PHASE8.md).

## Built (9a, 2026-10-15)

- **Core:** `src/core/st_queue.{h,c}`: queue names, entry numbers, status names from
  QUIDEF. **Platform:** `st_plat_queue_enum`, `_queue_get` (with its jobs), `_job_get`
  (with its files). **API:** three endpoints (api.md). **View:** `www/js/queues.js`.
- **Tests:** 343 unit; `make ui-test` 21 ok; on x86 `tests/vms/phase9_live.py` 9 ok, 0
  failed (held jobs of STEWARD_TEST's and the work account's, deleted after).
- **Found by the live test** (NOTES.md): an exact-name search keeps no context for the
  job or file walk after it unless `QUI$M_SEARCH_WILDCARD` is given; a missing entry is
  `JBC$_NOSUCHENT`.

Kit T0.8-0 (2026-10-15), built by `tools/kit.sh x86` (343 native checks), SHA-256
`e8fea23b2aa2849b0e320b0b82afddf004234c313912435d54deffaa9982638e`, for the browser
checks.

## Exit (9a)

- Queues, a queue's jobs and one job match `SHOW QUEUE/ALL/FULL` and `SHOW
  ENTRY/FULL`, for STEWARD_TEST and for STEWARD_ADM with SYSPRV.
- Another's job is shown as inaccessible, as at a terminal.
- Browser checks (the user's); the security gate.

## 9a closed (2026-10-15)

On the installed kit T0.8-0, the user's browser checks: the four queues; as
STEWARD_TEST the work account's jobs in X86VMS_BATCH inaccessible; as STEWARD_ADM with
SYSPRV readable, a job matching `SHOW ENTRY/FULL`; an inaccessible job by entry
refused with NOPRIV. `phase9_live.py` 9 ok; `phase7_live.py` 20 ok against the
installed helper procedure (its new process name). Security gate: security.md Phase 9
section and invariant; the review runs with 9b's.

## 9b: changes (started 2026-10-15)

**Probe** (`probes/probe_sndjbc.c`), from my all-privileged process, on held jobs
submitted for the purpose and a test queue the user agreed to (`STEWARD_P9B_TEST`,
created stopped and empty, deleted after):

| Persona, switched on | Target | Answer |
|---|---|---|
| STEWARD_TEST, none | its own held job: release | NORMAL (it then ran: it only exits) |
| STEWARD_TEST, none | its own held job: delete | NORMAL |
| STEWARD_TEST, none | my held job: delete | JBC NOPRIV |
| STEWARD_ADM, none | STEWARD_TEST's held job (its group): hold, delete | JBC NOPRIV (the group may read, G:R, not change) |
| STEWARD_ADM, none | my held job: delete | JBC NOPRIV |
| STEWARD_ADM, SYSPRV | my held job: delete | NORMAL |
| STEWARD_TEST, none; STEWARD_ADM, none | the test queue: start, stop | JBC NOPRIV |
| STEWARD_ADM, SYSPRV | the test queue: start, then stop | NORMAL (S:M) |

Hold on an executing job: `JBC$_EXECUTING`. `QUI$_GENERIC_TARGET` on SYS$BATCH gave the
12 bytes `X86VMS_BATCH` (no padding); `F$GETQUI` shows several as a comma-separated
list.

**Design** (D17): `POST api/v1/jobs/{entry}/hold` and `/release`, `DELETE
api/v1/jobs/{entry}`, `POST api/v1/queues/{name}/stop` and `/start`, by `$SNDJBC` under
the persona, audited, the browser asking first. Steward refuses (409), whatever the
viewer holds, to stop SYS$BATCH (or what it translates to in the system table) and the
execution queues it feeds: STEWARD$STARTUP submits the pool's start job there (the
user's choice, 2026-10-15, after OPCOM). Starting a queue is never refused.

**Built (2026-10-15):** the five endpoints, the buttons and dialogs. Tests: 358 unit,
56 API, 23 UI; on x86 `phase9b_live.py` 14 ok, 0 failed (held jobs and a test queue
it created and deleted; the start-up queues asked to stop only as STEWARD_TEST).

**Exit (9b):**
- Each change matches SET ENTRY/HOLD and /RELEASE, DELETE/ENTRY, STOP/QUEUE and
  START/QUEUE: what the queue manager refuses is refused, what it allows happens.
- Steward's start-up queues are never stopped through Steward.
- Every change audited; browser checks; the security gate with a review of Phase 9.

