# CLAUDE.md

Working notes for vms-steward: browser-based OpenVMS system management, served by
vms-lighttpd. `README.md` says what it is; `docs/PLAN.md` is the phased plan;
`docs/DECISIONS.md` records every decision with the alternatives considered. Read the
plan and the decisions before starting work. Work phase by phase; stop and ask at each
phase exit.

This is green-field code, not a port: there is no upstream tarball, no `patches/` and no
`staging/`. It aims at the ground VSI's WebUI covers but is **not** WebUI and must never
be presented as, named like, or derived from it. Do not copy VSI WebUI code, API paths,
documentation text or UI assets.

## Ground rules (from the sibling vms-* repos)

- **Use `tools/vms.sh`** for remote work; never raw `ssh host cmd`, never `WAIT` over ssh.
  Run long jobs with `run_in_background`.
- **Committed files must not contain real node details** (they live in the git-ignored
  `tools/nodes.conf`), nor credentials, nor passwords used in probes. Use `<x86-host>`.
- **Nothing destructive or system-wide on the nodes** without asking: no UAF or rights
  database changes except to accounts/identifiers the user has named for testing, no
  INSTALL, no system logical names, no new accounts. The live board (vms-lighttpd on x86)
  is the user's: read its logs, never touch its files or processes.
- Every decision goes in `docs/DECISIONS.md`; every surprise from the platform goes in
  `docs/NOTES.md` with how it was observed.
- Prefer a 20-line probe in `probes/` over speculation. Do not claim something works until
  a test on the node shows it.

## Hard constraints

- **C99, VSI C, 32-bit pointers** (D3). No C11, no VLAs, no anonymous unions. The Linux
  build uses `-std=c99 -pedantic -Wall -Wextra`; do not weaken it.
- **`src/core/` does no I/O** and has no platform dependencies: FastCGI framing, HTTP
  request/response, routing, JSON, validation and error mapping are pure and unit-tested
  on Linux.
- **`src/plat/st_platform.h` is the entire OS surface** and contains no VMS types.
  `src/plat/vms/` implements it with system services; `src/plat/stub/` is an in-memory
  fake used for Linux tests and front-end work.
- **Wire formats (FastCGI records) use explicit offsets and byte order**, never packed
  structs.
- **Every request runs under the caller's persona** (D2), and the persona is reverted on
  every path, including errors. A request that ends with a foreign persona still assumed
  is a security bug, not a leak.
- **Never log, store or echo a password.** Scrub buffers with `st_zero`, not `memset`
  (a dead store the compiler may remove).

## OpenVMS

You can reach the x86 node only through `tools/vms.sh`. Undefined symbols are *warnings*
on VMS: the build procedure must check `$SEVERITY` after every LINK. MMS does not track
flags: build from CLEAN after changing headers or qualifiers.

## Commits

Commit in logical steps with messages that explain why, particularly the reasoning behind
a platform workaround, and record what was verified and how. Don't push without the user
asking.

## VMS pitfalls found here

- **Never name a DCL symbol after a verb the procedure uses.** A symbol `RUN` turned
  `RUN/DETACHED` into an invalid command (`%DCL-W-IVVERB`), and the pool printed
  "started" for processes that never existed. Check `$STATUS` after creating one.
- **Do not use ACCOUNTING to find out why a process died:** it runs for many minutes on
  these nodes. Read the process's /OUTPUT log, or start a minimal detached process
  that writes one. If you cut a remote command short, stop the VMS process it
  started (by PID, your own only).
- **`#include "../x.h"` does not work in VSI C:** use bare names and include directories.
- **The C RTL lowercases unquoted `argv`.** Compare command-line arguments
  case-insensitively.
- **UAF dates are local time**, and the C RTL has no time zone rules here
  (`decc$fix_time` is a no-op). Convert with the system's current offset
  (`st_plat_vms.c`, `local_offset`).
- **Take item codes and masks from the headers on the node** (`LIBRARY/EXTRACT` from
  `SYS$STARLET_C.TLB`), never from memory: DISUSER is `UAI$M_DISACNT`.
