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
