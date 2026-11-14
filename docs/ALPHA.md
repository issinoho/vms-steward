# Alpha port: status

Started 2026-11-14. The node: AXPBOX, an AlphaServer DS10L (Charon-AXP), OpenVMS
V8.4-2L2, VSI C V7.4-002, VSI SSL3, TCP/IP V6.0-31. `tools/nodes.conf` entry `alpha`.
Findings, each with how it was observed, are in NOTES.md (2026-11-14 entries).

## Verified

- **Probes:** all sixteen of `probes/run_probes.com` build; `probe_rmi` run unprivileged:
  `RMI$_FRLIST` and `RMI$_MODLIST` take only a longword (NOTES.md).
- **Build:** the same sources, with two Alpha changes: the `$GETRMI` longword retry, and
  `/FLOAT=IEEE_FLOAT` (Alpha's C defaults to G_FLOAT). `build_vms CLEAN`, then `build_vms
  TEST`: `BUILD-OK`, no warnings, `528 checks, 0 failed`, `TEST-OK`.
- **Live, read-only, as IAIN through `api_probe`:** `/api/v1/system` (node AXPBOX, arch
  Alpha, AlphaServer DS10L, memory free = SHOW MEMORY) and `/api/v1/monitor` twice 10 s
  apart (free memory right, CPU modes 100 ticks a second).

## Not yet

- The phase live tests (`tests/vms/phase*_live.py`): they need the test accounts of
  `tests/vms/test_accounts.com` on the node, a UAF change.
- The kit: `tools/kit.sh` drives the build with interactive DCL, which is unreliable on the
  Alpha; vms-beszel's moved to batch jobs.
- A web front end. There is no lighttpd for Alpha yet (vms-lighttpd has no AXPVMS kit), and
  nothing else serves HTTP on AXPBOX.
