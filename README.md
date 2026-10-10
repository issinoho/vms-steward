# vms-steward

Browser-based system management for OpenVMS, served over HTTPS by
[vms-lighttpd](https://github.com/issinoho/vms-lighttpd) as a FastCGI service with a
REST API and a static web front end.

Users sign in with their own OpenVMS username and password, checked by `SYS$ACM`. Every
request then runs under that user's persona, so OpenVMS itself decides what they may
see and change.

## Status

Phase 0 (scaffolding and platform probes). Nothing is usable yet. See
[`docs/PLAN.md`](docs/PLAN.md).

| Area | Status |
| --- | --- |
| Scaffolding, sign-in, sessions | planned (Phase 1) |
| Users and rights identifiers | planned (Phases 2-4) |
| Access history: who connected, when, how (SSH, TELNET, FTP, DECnet, batch, Steward) in one view | planned (Phase 6) |
| Logical names, processes, queues, SYSGEN, licences, products, monitoring, error log, terminal | later |

## Platform

OpenVMS x86-64 first (VSI C, VSI TCP/IP Services, VSI OpenSSL 3). The code is portable
C99, and the service also builds and runs on Linux against an in-memory stub platform
for development and tests.

vms-steward is an independent project. It is not affiliated with VMS Software Inc. and is
not derived from any VSI product.

## Licence

MIT. See `LICENSE`.
