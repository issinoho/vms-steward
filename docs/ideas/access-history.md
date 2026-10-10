# Access history: who reached the system, when, and by which route

**Status:** on the roadmap at the user's request (2026-10-10). Design notes only;
nothing here is decided until its probes have run.

## The problem

OpenVMS records remote access, but in several places, each in its own format, and none
of them answers "who got in, when, from where, and how" by itself:

| Source | What it knows | Snag |
|---|---|---|
| Security audit journal (`SECURITY.AUDIT$JOURNAL`, `ANALYZE/AUDIT`) | LOGIN, LOGFAIL, LOGOUT and BREAKIN events with username, terminal, remote node/address, logon type | only what `SET AUDIT` enables; binary records |
| TCP/IP Services SSH server logs | SSH sessions, client address, key or password, sftp/exec/shell | text logs, version-specific layout |
| TELNET, FTP, rlogin | sessions via their own logs or audit events | some only through audit |
| Accounting (`ACCOUNTING`) | process and image records, interactive/batch/network | **far too slow to query live** on these nodes (user, 2026-10-10) |
| `OPERATOR.LOG` | OPCOM messages, including security alarms | free text |
| Intrusion database (`SHOW INTRUSION`) | current suspects and intruders by source | transient: entries expire |
| Steward's own audit log | sign-ins through Steward, with the browser address behind the proxy (D7) | only Steward |
| Live processes (`$GETJPI`) | who is on now, terminal, remote host | current only |

## Target

One view, newest first: **time, user, route** (SSH shell, SFTP, TELNET, FTP, DECnet,
Steward, batch, ...), **from** (address or node), **outcome** (success, failure, breakin,
still connected), and **duration**. It filters by user, route, address and time, and
links through to the underlying records. Failures and intrusions should stand out.

## Shape (to be tested)

- **Collect incrementally; don't query at view time.** A collector reads each source
  from where it last stopped, normalises the events, and appends them to Steward's
  own indexed store. The view reads only that store, so it stays fast however slow a
  source is. Accounting is never read on demand.
- **Prefer the security audit journal** as the backbone. It is OpenVMS's own record
  of logins and failures across routes. Other sources add detail it lacks, such as SSH
  method and SFTP versus shell. A probe must establish what this node's `SET AUDIT`
  already captures and what enabling LOGIN/LOGFAIL/LOGOUT for all classes would cost.
- **Privilege stays with OpenVMS (D2).** Reading the journal and other users' logs
  needs SECURITY or READALL, which the web service must not hold. So the collector
  runs as its own detached process under a separate account. The store it writes is
  protected by an ACL granting read to holders of an identifier (for example
  `STEWARD$ACCESS_VIEW`). Steward then reads it under the viewer's persona, and the OS
  decides who may see the history.
- **Correlation:** match SSH log sessions to audit LOGIN events by time, username
  and address, so one connection appears once with its route detail.

## Probes before design

1. What `SHOW AUDIT` has enabled on the node, and what LOGIN/LOGFAIL/LOGOUT records
   carry for SSH, TELNET, network and batch logins.
2. Whether the journal can be read incrementally from a program (record layout, the
   `ANALYZE/AUDIT/BINARY` output, or a supported interface), and how fast that is
   compared with `ANALYZE/AUDIT`.
3. Where TCP/IP Services V6.0 writes SSH session logs, their format, and whether
   they rotate.
4. Retention: how far back each source goes, and how big the store gets per month.
