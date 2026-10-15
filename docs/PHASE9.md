# Phase 9: batch and print queues

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

## Exit (9a)

- Queues, a queue's jobs and one job match `SHOW QUEUE/ALL/FULL` and `SHOW
  ENTRY/FULL`, for STEWARD_TEST and for STEWARD_ADM with SYSPRV.
- Another's job is shown as inaccessible, as at a terminal.
- Browser checks (the user's); the security gate.
