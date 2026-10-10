# vms-steward

Browser-based system management for OpenVMS, served over HTTPS by
[vms-lighttpd](https://github.com/issinoho/vms-lighttpd) as a FastCGI service with a
REST API and a static web front end.

Users sign in with their own OpenVMS username and password, checked by `SYS$ACM`. Every
request then runs under that user's persona, so OpenVMS itself decides what they may
see and change.

## Status

Phase 1 (service skeleton and sign-in) is built and running on OpenVMS x86-64 behind
lighttpd, as a least-privilege service account. Its exit checks through nginx proxy
manager are in progress. See [`docs/PLAN.md`](docs/PLAN.md), [`docs/api.md`](docs/api.md)
and [`docs/security.md`](docs/security.md).

| Area | Status |
| --- | --- |
| Scaffolding, sign-in, sessions | built; exit checks in progress (Phase 1) |
| Users and rights identifiers | planned (Phases 2-4) |
| Access history: who connected, when, how (SSH, TELNET, FTP, DECnet, batch, Steward) in one view | planned (Phase 6) |
| Logical names, processes, queues, SYSGEN, licences, products, monitoring, error log, terminal | later |

## Building

```sh
make test            # core unit tests (Linux, stub platform)
make api-test        # the real server over FastCGI
make audit           # analyzers, sanitizers, fuzzing, project rules (D8)
make dev             # the front end at http://127.0.0.1:8080/ on the stub platform
```

On OpenVMS: `@BUILD_VMS TEST` (VSI C, OpenSSL 3). The pool is run by
`vms/steward_pool.com` behind lighttpd (`vms/steward.conf`).

## Platform

OpenVMS x86-64 first (VSI C, VSI TCP/IP Services, VSI OpenSSL 3). The code is portable
C99, and the service also builds and runs on Linux against an in-memory stub platform
for development and tests.

vms-steward is an independent project. It is not affiliated with VMS Software Inc. and is
not derived from any VSI product.

## Licence

MIT. See `LICENSE`.
