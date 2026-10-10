# Notes

Platform findings, each with how it was observed. Phase exits are recorded here too.

## VSI C does not resolve `../` in `#include "..."` (2026-10-10)

`#include "../core/st_http.h"` failed with `%CC-F-NOINCLFILEF` on VSI C V7.7-003 x86-64,
from `[.src.svc]`. Includes in the same directory worked. All project includes are now
bare names (`#include "st_http.h"`), with the directories given as `-I` in the Makefile
and `/INCLUDE_DIRECTORY` in `build_vms.com`. Keep both lists in step.

## `RUN/DETACHED LOGINOUT` without `/AUTHORIZE` ignores the UAF privileges (2026-10-10)

After SYSPRV was added to STEWARD's authorized privileges, the pool (started by
`SUBMIT/USER=STEWARD`) still showed `F$GETJPI(pid,"AUTHPRIV")` =
`DETACH,TMPMBX,NETMBX`. Without `/AUTHORIZE`, LOGINOUT gives the detached process
the creator's privileges, so the batch job's *current* (default) set became the
child's *authorized* set. With `/AUTHORIZE` the process logs in properly:
AUTHPRIV = `DETACH,TMPMBX,NETMBX,SYSPRV`, CURPRIV = `DETACH,TMPMBX,NETMBX`, and
the quotas come from the UAF, so the pool no longer sets them. A RESTRICTED
account needs a LOGIN.COM for this, which `[STEWARD]` has.
