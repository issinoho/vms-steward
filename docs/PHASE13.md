# Phase 13: monitoring

**Status: planning (2026-10-17).** D21 proposed; questions for the user below.

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

## Exit (13a)

- `GET api/v1/monitor` through `api_probe` on x86, against `MONITOR /SUMMARY` taken at
  the same time (rates within MONITOR's spread), for STEWARD_TEST and STEWARD_ADM.
- The rate module's unit tests (wraps, restarts, processes coming and going); a UI
  test on the stub.
- A kit and the user's browser checks.
