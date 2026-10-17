# Phase 13: monitoring

**Status: closed (2026-10-17).** 13a on the user's browser checks of the 0.12.0 kit,
13b (history recorded on the node) on those of the 0.13.0 kit. The user approved D21
and its suggested answers ("go"), then D22 and its ("im good with that").

CPU, memory, paging and I/O over time, as MONITOR shows them, in the browser. The
dashboard (Phase 5) already shows one snapshot: CPU busy between two polls, memory,
page files, disks. Monitoring adds the breakdown and the history.

## What the probes found (NOTES.md)

| Source | Who may read it | Notes |
|---|---|---|
| `$GETRMI`: CPU mode counters (`RMI$_CPUKERNEL` … `CPUIDLE`), `DIRIO`, `BUFIO`, `FAULTS`, `PREADIO`, `PWRITIO`, `ISWPCNT`, `MBREADS`/`MBWRITES`, `FRLIST`, `MODLIST`, process-state counts | anyone: no privilege for any item | counters since boot, so rates come from two readings; mode counters are ticks summed over CPUs (100 a second a CPU); some items want 4-byte buffers, some 8; the return length is written as a longword |
| `RMI$_CPUINTSTK` | anyone | negative on the x86 VM; MONITOR shows 0.00. Shown as 0 |
| `RMI$_MODES` (each CPU) | anyone | layout only partly settled: per-CPU MP synch, kernel, exec, super, user add up; idle does not, simply |
| `RMI$_DISKS` | — | BADPARAM |
| `$GETDVI` `OPCNT` for each disk | anyone | a counter; the dashboard already walks the disks |
| `$GETJPI`, each process: CPU time, direct and buffered I/O, page faults | as the processes view (Phase 8): what the persona may see | the rest counted as hidden |
| MONITOR recording, TDC, T4 | — | none running or installed: nothing on the node keeps history |

`probes/probe_rmi.c`, with everything off but TMPMBX and NETMBX; `MONITOR
MODES,SYSTEM,IO/SUMMARY` as the reference.

## Design (D21, proposed)

- **`GET api/v1/monitor`**: one reading of the raw counters and when it was taken:
  CPU modes, process states, memory lists, paging and I/O counters, each disk's
  operation count, and each process the viewer may see with its CPU time, I/O and
  faults (and how many are hidden). It does no arithmetic and keeps no state, so any
  pool process can answer it. In-process, under the persona; no helper.
- **The browser keeps the history.** While the Monitoring page is open, it polls
  (every 5 s by default) and works out rates from consecutive readings, keeping the
  last 30 minutes (360 readings at 5 s) in memory. Closing the page drops the history.
  Polls are not activity for the session's idle timeout, as for the dashboard.
- **The page**, MONITOR's classes as charts drawn in SVG (no library, as the
  dashboard's gauges):
  - CPU: busy by mode (interrupt, MP synch, kernel, exec, super, user), stacked, as a
    share of all CPUs;
  - process states: computable, LEF, HIB, current, and the rest;
  - memory: in use, free, modified; paging: faults, page reads and writes, inswaps;
  - I/O: direct, buffered, mailbox; each disk's operations a second;
  - the busiest processes over the last interval, by CPU and by I/O, as far as you
    may see them (from the counters' changes, by PID).
- **Rates in the browser**: the arithmetic (deltas, the wrap of 32-bit counters, per
  second, a process that went or came) in a small JS module of its own, unit-tested.

Alternatives considered:
- **A recording process on the node** (a detached Steward sampler writing a file):
  hours or days of history, seen by everyone, but a new long-running process, a file
  that grows, and privileges for a process no viewer owns. A possible 13b, if wanted.
- **MONITOR /RECORD**: the user would start it system-wide, and its record format is
  not documented.
- **Running MONITOR in the D14 helper** and parsing its screens: slow (a process per
  reading), and the counters are open to anyone in-process anyway.
- **Each CPU separately** (`RMI$_MODES`): left out until its layout is settled.

## Questions for the user

1. **History.** Keep it in the browser (30 minutes while the page is open, nothing on
   the node), or should Steward record on the node so history survives (a sampler
   process: a bigger change, 13b)?
2. **Interval.** 5 s by default, with 2, 10 and 30 s to choose from?
3. **Busiest processes.** Include the table (only the processes you may see), or keep
   monitoring to system-wide figures?
4. **Per-CPU.** Leave each CPU's figures out for now (the layout is unsettled), or
   probe further first?

Suggested answers: 1 in the browser; 2 yes; 3 include; 4 leave out for now.

Answers (2026-10-17, "go"): the suggestions, all four.

## Exit (13a)

- `GET api/v1/monitor` through `api_probe` on x86, against `MONITOR /SUMMARY` taken at
  the same time (rates within MONITOR's spread), for STEWARD_TEST and STEWARD_ADM.
- The rate module's unit tests (wraps, restarts, processes coming and going); a UI
  test on the stub.
- A kit and the user's browser checks.

Live test: `tests/vms/phase13_live.py x86` 14 ok, 0 failed (against MONITOR
MODES,SYSTEM,IO/SUMMARY over the same 21 s: idle 46.5 vs 48.8, buffered I/O 2,570/s vs
2,621; STEWARD_TEST its own processes only, STEWARD_ADM everyone's with WORLD).

Kit T0.12-0 (0.12.0), built by `tools/kit.sh x86` (417 native checks), SHA-256
`cb3379ea64b0ae5815a4dd8d27125d857d6322f574ff2490182244ea6deb1101`, for the browser
checks. It also carries the `item_u64` return-length fix (NOTES.md).

Browser checks: the user installed the kit on x86, restarted the pool and confirmed
the Monitoring page (2026-10-17). 13a closed.

## 13b: history recorded on the node (D22, proposed)

13a's history lasts while the page is open. 13b records the system-wide counters on
the node, so the page can show the last hours or days whoever looks and whenever.

- **A recorder process, `STEWARD_R<base-port>`** (process names stop at 15
  characters, so not `STEWARD_RECORDER`), started and stopped with the pool by
  `STEWARD_POOL.COM` (same DCL restart loop and stop file), running the same image as
  `STEWARD -r`. It is the service account but switches every privilege but TMPMBX and
  NETMBX off at start, in the permanent mask too, and checks: it never assumes a
  persona, and `$GETRMI` and `$GETDVI` need no privilege. (The account stays
  authorized for IMPERSONATE, so this is the recorder's own discipline, as SYSPRV is
  the pool's, D2.) Every interval (60 s by default, on the clock's
  boundaries) it takes one reading, the same `st_plat_monitor` the page uses, and
  writes it.
- **System-wide figures only; no processes.** The recorder sees every process, but
  what a viewer may see of one is decided by `$GETJPI` as the viewer (D10, D16), and a
  process that has ended can no longer be asked. So per-process history is not kept;
  the busiest-processes tables stay live-only.
- **A fixed-size ring, `[.RUN]MONITOR.DAT`**: an RMS indexed file of fixed records
  (as the session store), keyed by slot, slot = (time / interval) mod slots; a header
  record (key 0) holds the interval and the number of slots. It never grows: 7 days
  at 60 s is 10,080 slots of about 1.5 KB, some 15 MB. Each record carries its own
  time, so a stale slot (the recorder was stopped, the interval changed) is simply
  skipped. Records are encoded with explicit offsets and byte order in core (as the
  FastCGI records), unit-tested; private to the service account, like the rest of
  `[.RUN]`.
- **`GET api/v1/monitor/history?minutes=N&points=P`**: up to P readings spread over
  the last N minutes (keyed reads, one per point), each the same raw counters as
  `GET api/v1/monitor` without the processes. Because the counters are cumulative,
  every *k*th reading still gives exact averages between them, so a week fits in 300
  points and `rates.js` works on it unchanged; gauges (memory, process states) are the
  values at each point. The pool opens the file at start, as the service account (as
  it opens the session store and the audit log), and reads it under the persona: it
  holds only what `$GETRMI` gives anyone, so any signed-in user may see it (D10).
- **The page**: a range choice beside the interval: *Live* (13a: 30 minutes from the
  browser, the busiest processes) or *6 hours*, *24 hours*, *7 days* from the
  recording, the same charts, refreshed each minute. Gaps (the recorder stopped, a
  reboot) show as gaps. Without a recording (recorder off, file not there yet) the
  ranges say so and Live works as now.
- **Settings** (`STEWARD_SETTINGS.COM`): `STEWARD_RECORD_SECS` (60; 0 turns the
  recorder off), `STEWARD_RECORD_DAYS` (7). `STEWARD$CONTROL STATUS` lists the
  recorder with the pool.

Alternatives considered:
- **Recording inside a pool process** (a timer AST): no extra process, but the AST
  could fire while a request's persona is assumed and write the file as the viewer;
  and each pool process would record, or they would have to agree which one does.
- **Daily sequential files**: simple appends, but they grow and need pruning, and
  finding a time means reading from the start.
- **MONITOR /RECORD**: system-wide, needs the user to run it, format undocumented.
- **Keeping rates rather than counters**: smaller, but the averages over a longer
  range then need weighting, and a reboot inside an interval is lost; counters let
  `rates.js` do all of it.

## Questions for the user (13b)

1. **On by default?** The recorder starts with the pool unless `STEWARD_RECORD_SECS`
   is 0; or off until the setting is made.
2. **Interval and retention.** 60 s for 7 days (about 15 MB, fixed)? Or e.g. 30 s for
   7 days (30 MB), or 60 s for 30 days (65 MB).
3. **Ranges on the page.** Live, 6 hours, 24 hours, 7 days?
4. **No per-process history** (as above): the busiest processes stay live-only.

Suggested answers: 1 on by default; 2 60 s for 7 days; 3 yes; 4 agreed.

Answers (2026-10-17, "im good with that"): the suggestions, all four.

## Exit (13b)

- The record encoding and slot arithmetic in core, unit-tested (wraps of the ring,
  stale slots, an interval change).
- On x86, in the work directory: a recorder run with a short interval writes a file
  that `api_probe` reads back through `GET api/v1/monitor/history`, the readings
  agreeing with `GET api/v1/monitor` taken alongside; the recorder holds no
  IMPERSONATE or SYSPRV (`F$GETJPI`); STEWARD_TEST reads the history.
- The pool procedure starts, lists and stops the recorder (in the work directory's
  test pool, not the user's).
- A UI test on the stub for the ranges; a kit and the user's browser checks.

Live test (13b): `tests/vms/phase13b_live.py x86` 19 ok, 0 failed. The recorder run for
40 s at 5 s wrote 9 readings, each within 6 ms of its boundary, with TMPMBX and NETMBX
only (current and permanent); STEWARD_TEST read them back through `api_probe`, and the
last agreed with a live reading taken 2.1 s later; the mode ticks between the first and
last came to 7,947 of the CPUs' 8,000; no processes in the recording; 1 minute in 2
points gave readings 30 s apart; without a file, `recording: false`. The work
directory's test pool (no FastCGI processes, base 19390) started STEWARD_R19390,
listed it with TMPMBX and NETMBX, recorded into its MONITOR.DAT (protection
S:RWED,O:RWED,G,W), stopped it, and did not start it with STEWARD_RECORD_SECS "0".
Linux: 447 unit checks (with the record format and ring), 56 API checks, the UI tests
(the ranges on the stub's made-up week, with its gap) and `make audit`.

Kit T0.13-0 (0.13.0), built by `tools/kit.sh x86` (447 native checks), SHA-256
`046fbaedeef3b06a0d9265f0e14d726240109c8f3b64db950e88de82392e8f33`, for the browser
checks.

Browser checks: the user installed the kit on x86, restarted the pool and confirmed
the Monitoring page's ranges (2026-10-17). 13b closed; Phase 13 done.
