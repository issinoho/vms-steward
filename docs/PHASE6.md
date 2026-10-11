# Phase 6: access history

Who reached the system, when, from where and by which route, in one view
(docs/ideas/access-history.md). These are the probe results so far, from the x86
node, 2026-10-11. All read-only.

## Sources, as found

| Source | What it gives | Found |
|---|---|---|
| **Accounting** (`SYS$MANAGER:ACCOUNTNG.DAT`) | One record per *finished* process: type (INTERACTIVE, NETWORK, BATCH, DETACHED, SUBPROCESS), username, UIC, start and finish time, elapsed time, terminal, **remote full name** (the client address), final status, images run. Also LOGIN_FAILURE. | All of these are enabled. An SSH session shows as a NETWORK process with `Remote full name: 192.168.0.131`. The old file had grown to 970,399 blocks and took minutes to query; the user rotated it on 2026-10-11 (19 blocks), and it now answers at once. |
| **Security audit journal** (`SYS$COMMON:[SYSMGR]SECURITY.AUDIT$JOURNAL`) | LOGFAIL and BREAKIN events, by login class (NETWORK, LOCAL, ...). Steward's own `$ACM` failures appear here too (STEWARD_ADM and STEWARD_NEW, 2026-10-11). | Only failures and break-ins are audited. **Successful LOGIN and LOGOUT are not enabled**, so the journal cannot show who got in. The journal is **3,188,696 blocks (~1.6 GB) and has never been rotated (since 2024-11)**. `ANALYZE/AUDIT/SINCE=-1:00` still answered in seconds. The record layouts (NSADEF and family) are in `SYS$LIB_C.TLB`, as UAFDEF was. |
| **VSI OpenSSH V9.9-2C** (`SSH$ROOT:[VAR]`) | A log per connection, `<node>_<client-host>_<pid>.log`: `Accepted publickey for iain from 192.168.0.131 port 36166 ssh2: ED25519 SHA256:...`, then the disconnect. The startup logs (`SSH$SSHD_STARTUP.LOG`) carry timestamped SFTP lines: session opened and closed, files opened. | The method and key are there, but the per-connection lines have **no timestamps** (the file's dates give the time). These are versioned files that get purged (64 on disk now), so they must be read before they go. |
| **Steward's audit log** | Sign-ins through Steward, with the browser's address behind the proxy (D7). | Already ours. |
| **Live processes** (`$GETJPI`, as the dashboard reads them) | Who is connected *now*, which accounting cannot show until the process ends. | Already read for the dashboard. |

## Decisions (user, 2026-10-11)

- **Read on demand, as the viewer** (D13): no collector, no new account.
- **The audit journal was rotated** (`SET AUDIT/SERVER=NEW_LOG`). The 1.6 GB
  `SECURITY.AUDIT$JOURNAL;2` is kept for the user to archive. Successful LOGIN
  auditing stays off, since accounting has the successful sessions.

## Reading the sources from C (2026-10-11)

**Accounting: `probe_acct`.** ACRDEF (SYS$STARLET_C, `__NEW_STARLET`). Each record is
a 12-byte header (type in bits 1-7 of the first word, subtype in bits 8-11, length,
event time), then packets with their own type and length.
- The **ID packet** holds the PID, UIC and offsets to the username, terminal, node,
  remote ID and queue, which are *counted strings*. The **remote full name** (the
  client address) is a *word-counted* string. The header does not say so; a raw dump
  of a record showed `0D 00 "192.168.0.131"`.
- The **resource packet** holds the start time and final status.
- The probe's output matched `ACCOUNTING/FULL` for the same record: PID 00007D59,
  17:26:09.11 to 17:29:00.44, remote IAIN at 192.168.0.131.
- An SSH session shows as a NETWORK process under the user, with the client address.
  The SSH server's own work is a NETWORK process under SSH$SSH, with the user's
  commands as SUBPROCESSes.
- **Not in accounting:** a failure through `$ACM` (non-dialogue: Steward's sign-in,
  and SSH password checks). A deliberate wrong password gave no ACR$K_LOGFAIL. These
  failures are only in the audit journal.

**Audit journal: `probe_audit`.** NSAMSGDEF (SYS$STARLET_C). Each record is a 20-byte
header (event type, subtype, packet count, size, version), then packets
`{size, type, data}`. **The size includes the 4-byte packet header.** The deliberate
failure parsed exactly as `ANALYZE/AUDIT/FULL` showed it:
- LOGFAIL NETWORK, 17:40:43.24, user STEWARD_TEST;
- remote nodename 127.0.0.1, remote username STEWARD;
- status `%X00D380FC` (`LOGIN-F-INVPWD`).

Both files are opened shared (`SHRGET|SHRPUT|SHRUPD`; the journal also with `UPI`) and
read with no record locks while their writers keep running.
