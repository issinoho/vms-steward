# Security: threat model and code audit programme

Steward lets a browser change who may log in to an OpenVMS system and with what
privileges. A bug in it is a privilege-escalation bug in the operating system, so
the code is audited continuously and at every phase gate (DECISIONS D8). This file
holds the threat model those audits work from, the checks that run, and the record
of what each audit found.

## Assets

1. **The authorization database** (SYSUAF, RIGHTSLIST) and everything it controls.
2. **Passwords** in transit through Steward (sign-in, later password changes).
3. **Sessions**: a session token is an authenticated OpenVMS identity for its
   lifetime.
4. **The service account's IMPERSONATE privilege**: with it, Steward can become any
   user without a password. Every check in D2 exists to keep that power on a leash.
5. **Intrusion detection** (D2): records must name the real client, or an attacker
   can hide, or lock everyone out.

## Trust boundaries

```
browser ─(1)─ nginx proxy manager ─(2)─ lighttpd ─(3)─ STEWARD.EXE ─(4)─ system services
                                                        (IMPERSONATE)     under a persona
```

1. Untrusted: everything from the browser, including headers it can set
   (`X-Forwarded-*`, `Origin`, cookies, JSON).
2. Proxy to lighttpd: trusted only for the proxies in `STEWARD_TRUSTED_PROXIES` (D7).
3. FastCGI over loopback: Steward refuses non-loopback peers, but still treats every
   byte as untrusted. The parsers are fuzzed.
4. The OS boundary: the persona makes OpenVMS do the authorization (D2). Steward's
   job is to get the *right* persona and to end it on every path.

## Attacker models

| Who | Can | Must not be able to |
|---|---|---|
| Local OpenVMS user | connect to 127.0.0.1, read world-readable files | reach the FastCGI ports directly and choose their own REMOTE_ADDR, which would let them guess passwords without triggering breakin evasion; read the session store or audit log |
| Anonymous on the network | send any HTTP, guess passwords | sign in without a password; probe which usernames exist; lock everyone out; hide behind the proxy's address |
| Signed-in unprivileged user | call any endpoint | do anything OpenVMS would refuse them at a terminal; act as another user; keep a session past logout or expiry |
| Malicious web page in the user's browser | make the browser send requests | ride the user's session (CSRF), read responses, frame Steward |
| Someone who can read a session store backup | read stored records | use them as live sessions (only token hashes are stored) |
| Someone who can write OpenVMS data Steward displays (owner fields, identifier names) | put markup or control characters there | inject into the page, the JSON, or the audit log |

## Security invariants (each is enforced and tested)

| Invariant | Enforced by | Tested by |
|---|---|---|
| Every request ends with no persona active | dispatcher; server exits if one leaks | unit `test_dispatch`, API suite |
| Personas begin and end only in the dispatcher | design | `audit_rules.sh persona-only-in-dispatcher` |
| The service's SYSPRV is on only around `$PERSONA_CREATE` (D2 amendment) | enabled and disabled around the call; process exits if it cannot disable; checked after every request | on VMS at the phase exit: `STEWARD_POOL STATUS` shows no SYSPRV |
| Only our lighttpd reaches the API (gateway secret) | dispatcher `via_gateway`; lighttpd overwrites the header | unit `test_gateway`; API "bypasses lighttpd"; on VMS, direct FastCGI 403 |
| Session store and audit log private to the service | pool default protection `(S:RWED,O:RWED,G,W)` and `[.RUN]` | directory listing at phase exit |
| A session can enable only privileges the user is authorized for (D9) | OpenVMS: `$SETPRV` under the persona is capped by the persona's authorized mask (probe_setprv); Steward also refuses unauthorized names up front | unit `test_privileges`; API "unauthorized privilege is refused" |
| Forwarded headers believed only from trusted proxies | `st_app_origin` | unit `test_proxy`, API "untrusted peer" |
| State changes need same origin and the session's CSRF token | dispatcher | unit and API suites |
| Sign-in failures are indistinguishable (wrong password, disabled, no such user, malformed) | `svc_session_login` | unit "disabled looks the same" |
| Expired passwords get no session | platform check after `$ACM` | unit, API, and on VMS at phase exit |
| Usernames are validated and upcased before `$ACM` or `$PERSONA_CREATE` | `st_valid_username` | unit |
| No password or token in logs, responses or freed memory | `st_zero`, `st_json_free` scrubbing | API "no password in the audit log"; `audit_rules.sh scrub-with-st_zero` |
| Data from OpenVMS never becomes markup | `dom.js` text nodes; JSON writer escapes `<>&`; CSP | `audit_rules.sh no-html-sinks`; unit writer test |
| Privilege masks carried as full quadwords | review | PHASE1 probe finding; review checklist |
| Read views add no access rules and hide nothing OpenVMS shows (D10): what a user sees is decided by the OS under their persona | design; the only reads are under the persona in the dispatcher | on VMS: PHASE2.md probes as STEWARD_TEST with and without GRPPRV; unit "an unprivileged user cannot list users" |
| SYSUAF is opened only under the persona, and closed before the request ends; it never takes a record lock | `st_plat_user_enum` opens, walks and closes in one call, with `RRL+NLK` | review |
| Query parameters that are present but unusable are refused, never ignored | `svc_query` | unit "an over-long filter is refused" |
| Names from the URL are validated before any system service sees them (usernames, identifier names) | `st_valid_username`, `st_valid_ident` | unit; API "encoded slash" |
| Every change runs under the caller's persona; OpenVMS refuses what they may not do | dispatcher (no change route is `R_NOPERSONA` except the password change, D11) | unit "cannot change even their own record"; on VMS `phase3_live.py` as STEWARD_ADM without SYSPRV and as STEWARD_TEST |
| CHANGE_PASSWORD is reached only after the current password has passed a sign-in check | `svc_password_change` | unit "a wrong current password looks exactly like a failed sign-in" |
| A user edit cannot silently overwrite one made since the page was read | ETag / If-Match | unit 428, 412, "the old ETag no longer works" |
| Holding attributes the identifier lacks are refused, not dropped | `attribs_value` | unit |
| Every change is audited, without passwords | handlers | API suite "no password reaches the audit log" |
| A failed create leaves nothing behind | `st_plat_user_create` undoes the record and identifier | unit "nothing was left behind"; on VMS `phase4_live.py` (PWDSYNTAX after `$PUT`) |
| Steward cannot delete the signed-in account or itself | `svc_user_delete` | unit 409s |
| The service's process and job logical names are never read or listed for a viewer | `st_valid_lnm_table`; `st_plat_lnm_get` translates only in a real table of LNM$SYSTEM_DIRECTORY | unit `test_lnm_parser` (the table checks); `phase7_live.py` "refused before OpenVMS is asked" |
| A listing of logical names is the viewer's own, run as them, with commands never built from input | the D14 helper: data-only mailboxes, checks in Steward and in `STEWARD_LNM.COM` | `phase7_live.py` |
| No helper process outlives its request | `st_plat_lnm_list` deletes it on timeout or error | `phase7_live.py` "no helper process left behind" |
| An inner mode is never quietly made user mode | `st_plat_lnm_define` and `_deassign` refuse supervisor and executive without SYSNAM, before OpenVMS is asked | unit "executive mode without SYSNAM"; `phase7b_live.py` "the user-mode name is untouched" |
| A logical name change never records its equivalences | `svc_logical_define`, `svc_logical_deassign` | API suite "without the equivalence"; `phase7b_live.py` "never an equivalence" |
| Steward's serving process is never shown as the viewer's | `st_plat_proc_enum` and `_get` leave out (404) the calling process | `phase8_live.py` "nothing switched on: none"; unit "only the viewer's own processes" |
| Steward's pool is never stopped through Steward | `svc_process_stop` refuses the service account's processes; `st_plat_proc_stop` the serving one | unit "Steward's own pool process: refused"; API suite; `phase8b_live.py` (on a test job named as the account) |
| A job the viewer may not read shows no more than its entry and status | `job_from_raw` (VMS) clears the rest when `QUI$M_JOB_INACCESSIBLE` is set; `st_plat_job_get` refuses it | unit "another group's inaccessible"; `phase9_live.py` "entry and status only" |
| Steward's start-up queues are never stopped through Steward | `queue_change` refuses `st_plat_startup_queues` before `$SNDJBC` | unit "a queue SYS$BATCH feeds: refused"; `phase9b_live.py` (asked as STEWARD_TEST only) |

## Phase 2 additions (users and identifiers, read-only)

- **New endpoints:** six GETs (docs/api.md). All of them need a session and run
  under the persona, and none changes anything.
- **New system services, all under the persona:** RMS `$OPEN`/`$GET` of SYSUAF,
  `$GETUAI`, `$IDTOASC`, `$ASCTOID`, `$FIND_HELD`, `$FIND_HOLDER`, `$FINISH_RDB`.
- **New data shown:** every UAF field AUTHORIZE shows, except password hashes and
  salts, which Steward never requests. It also shows identifier names, values,
  attributes and holders. Owner names, LGICMD and directory strings are set by
  whoever manages the UAF. They reach the page only through the JSON writer and
  `dom.js` text nodes; an `href` is always `#/...` plus `encodeURIComponent`.
- **What OpenVMS reveals, accepted as it is (D10):** a signed-in user can tell
  whether a username exists (`$GETUAI` says RNF before checking privilege), and can
  read the whole rights database. Neither is new: both are available at a terminal.
  Before sign-in nothing changes.
- **Cost:** a list makes one `$GETUAI` per SYSUAF record it scans, and an identifier
  list reads the whole rights database (capped at 8192 entries per request). A
  signed-in user can make the service do that work. Pages are capped at 200, and
  the pool serves one request per process, so a heavy user slows only their own
  process. Phase 5's load run measures it.

## Phase 3 additions (changes)

- **New endpoints:** nine changes (docs/api.md). Eight need a session, CSRF and the
  persona. One, `POST api/v1/session/password`, is public, because an expired password
  cannot sign in; it authenticates with the current password (D11).
- **New system services, all under the persona except the password change:**
  `$SETUAI`, `$ADD_IDENT`, `$MOD_IDENT`, `$REM_IDENT`, `$ADD_HOLDER`, `$MOD_HOLDER`,
  `$REM_HOLDER`. `$ACM CHANGE_PASSWORD` runs as the service, after a sign-in check
  of the current password.
- **The power this adds:** a user with SYSPRV can do through Steward what AUTHORIZE
  lets them do, including granting privileges. That is OpenVMS's model, and Steward
  does not narrow it (D2, D10). What Steward must guarantee is that only that user's
  own persona does it. The dispatcher's invariants, unchanged since Phase 1, are what
  this phase relies on most.
- **Lockout:** CHANGE_PASSWORD charges failures to the account, so it is never
  reached with an unverified current password (D11). Sign-in-style failures are
  charged to the client.
- **Lost updates:** a user edit carries the ETag of what was read. The compare and
  the `$SETUAI` are not atomic, since OpenVMS offers no lock that AUTHORIZE also
  honours, so two edits within milliseconds could still interleave. The ETag stops
  the common case: an edit made from a page that is minutes old.
- **Passwords:** taken from the JSON, converted, passed to the system service and
  scrubbed (`st_zero`), with the JSON document scrubbed when freed. They are never
  audited, logged or echoed.

## Dashboard additions (D12)

- **New endpoint:** `GET api/v1/system`, which needs a session and runs under the
  persona. It shows system configuration and usage that OpenVMS gives any user
  (`$GETSYI`, `$GETRMI`, `$GETDVI`, `$GETQUI`). Processes are limited to what the
  persona may see.
- **New header:** `X-Steward-Background: 1`. All it changes is that the request does not
  refresh `last_seen`. A client can only *shorten* its own session with it, never
  lengthen one, and it has no effect without a valid session and CSRF where needed.
  Unit "a background poll ... does not count as activity".

## Phase 4 additions (create, copy, delete; D6)

- **New endpoints:** `POST api/v1/users`, `DELETE api/v1/users/{u}` and
  `GET api/v1/uic/next`. All need a session, CSRF and the persona.
- **New operations, under the persona:** RMS `$PUT` and `$DELETE` on SYSUAF, from
  UAFDEF's own record layout (`SYS$LIB_C.TLB`), plus `$ADD_IDENT`, `$REM_IDENT`,
  `$REM_HOLDER` and `LIB$CREATE_DIR`. This is the first time Steward writes a raw
  system record. The record is the template's own, with the name, UIC and owner
  changed and the history cleared, so no field is invented.
- **Atomicity:** a create either completes or leaves nothing. This was verified on the
  node with a password OpenVMS refused after the `$PUT`: no record and no identifier
  remained.
- **Safety rails (not access control):** no deleting your own account or the
  service's; no UIC already in the rights database; a delete must carry the ETag of
  the record shown; no directory without a device (see the audit record).

## Phase 6 additions (access history; D13)

- **New endpoint:** `GET api/v1/access`, which needs a session and runs under the
  persona. It only reads.
- **New data shown:** who signed in, from which address and how, and failed sign-ins
  with the username tried. This is sensitive: a failed sign-in's username is sometimes
  a password typed into the wrong box. It comes only from files OpenVMS protects
  (accounting, the security audit journal, OpenSSH's logs, Steward's own log), all
  opened **as the viewer**, so only someone OpenVMS already lets read those files
  (SYSPRV or READALL, switched on) sees it. Unit "without privilege each file source
  is refused"; live "STEWARD_TEST (no privileges): each file refused by OpenVMS".
- **No new privilege, no collector:** nothing runs in the background, and the service
  account gains nothing. The live list is `$GETJPI` as the viewer, limited as at a
  terminal (WORLD or GROUP to see others).
- **Files read, never written:** opened shared (`SHRGET|SHRPUT|SHRUPD|UPI`) with
  no record locks, so the accounting manager, the audit server and sshd keep writing.
- **Parsing untrusted bytes:** every length and offset in an accounting or journal
  record is checked against the record before use; strings are copied with a bound
  and reduced to printable ASCII. A log line is read into a bounded buffer and parsed
  with bounded copies. Steward's log values are unescaped from its own `kv` format.
- **Bounds:** at most 6,000 process records, 256 SSH logs and 1,000 failures are held
  per request (static, not heap), and at most 2,000 events are returned.
- **Cost:** each request reads the files whole. 24 hours on the x86 node took 0.69s.
  A very large journal or accounting file makes this slow, as it makes ANALYZE/AUDIT and
  ACCOUNTING slow; the answer is to rotate them (PHASE6.md).

## Phase 7 additions (logical names, read-only; D14)

- **New endpoints:** three GETs (docs/api.md). They need a session, run under the
  persona, and change nothing.
- **New system services, under the persona:** `$TRNLNM` in-process, and, to list a
  table, `$CREMBX`, `$CREPRC` (detached, `LOGINOUT`), `$QIO` on the mailboxes,
  `$SETIMR`/`$CANTIM` and `$DELPRC`.
- **The helper process.** OpenVMS cannot list a table through a service, so the listing
  runs in a short-lived detached process created while the persona is assumed. That
  process *is* the viewer: their UIC, and their authorized privileges as LOGINOUT
  gives them. It runs the fixed procedure `STEWARD_LNM.COM` from the kit, and `SHOW
  LOGICAL` shows what OpenVMS lets the viewer see. Steward never builds a command line.
  - **Data only.** The table, the pattern and the session's privileges go as three
    mailbox messages. The procedure checks each against its own character set (`A-Z
    0-9 $ _ * %` for the first two; letters, `_` and `,` for the privileges), as
    Steward did, before DCL sees them. Nothing that would be a qualifier, a symbol or
    a second command gets through (live: "a table with a qualifier in it", "a pattern
    with a quote").
  - **The mailboxes** are temporary, created under the persona, and protected for
    system and owner only. Only the viewer's own processes could touch them.
  - **The output is untrusted.** The viewer's own login procedures run before the
    helper procedure, and the reply mailbox is the viewer's, so they could write
    anything into their own listing. It is parsed with bounded copies (the parser is
    fuzzed, each line in a buffer of exactly its length) and goes back only to that
    viewer.
  - **Never left behind, never longer than 30 s.** Steward waits on the reply, a
    30-second timer and the helper's termination mailbox together, and checks the
    deadline after every wake, so a helper that floods the reply mailbox is stopped
    too. One that ends without answering is noticed at once. On a timeout or error
    it deletes the helper by PID (live: "no helper process left behind", and with
    `PHASE7_FAILDIR` the dead and flooding helpers in `probes/`).
  - **The procedure is fixed.** Its path is a constant in the server, never taken
    from a logical name; only the test probe can swap it.
  - **The viewer's symbols do not reach it.** The procedure starts with `SET
    SYMBOL/SCOPE=(NOLOCAL,NOGLOBAL)`.
  - **Cost to the viewer.** Each listing is a short login of the viewer: accounting
    records it, and it counts against their process and job limits while it runs.
    The pool serves one request per process, so a user can keep at most one helper
    per pool process running.
- **Privileges (D9).** The helper starts with the account's default privileges only.
  The privileges switched on in the session are sent as data, and the procedure runs
  `SET PROCESS/PRIVILEGE`, which OpenVMS caps at the account's authorized set (live:
  STEWARD_ADM sees group 1's table only with SYSPRV switched on).
- **The service's own names.** The service keeps its settings, among them the gateway
  secret, in process logical names. Under a persona, `$TRNLNM` in the process table
  would read them. `st_valid_lnm_table` refuses the process and job tables, every
  search list through them (`LNM$FILE_DEV`, `LNM$DCL_LOGICAL`, ...), and every job
  table by its own name (`LNM$JOB_<address>`; one is the pool's job's), before any
  service is called. `st_plat_lnm_get` also translates only in a real table of
  `LNM$SYSTEM_DIRECTORY` (not an alias, not a search list, not the directory itself).
  The translation chain looks only in the viewer's group table, the system table and
  the cluster table.
- **What OpenVMS says, accepted as it is.** `SHOW LOGICAL` answers IVLOGTAB, as a
  warning, both for a table that does not exist and for one the viewer may not read.
  Steward gives 404 for both, so it reveals no more than the terminal does.
- **New data shown:** names and equivalences the viewer can already read. Equivalence
  strings are written by whoever defines the names, may hold any byte, and reach the
  page only through the JSON writer and `dom.js`.

## Phase 7b additions (define and deassign; D15)

- **New endpoints:** `PUT api/v1/logical`, `DELETE api/v1/logical`, and `GET
  api/v1/logical` (reading by query). The two changes need a session and the CSRF
  header, run under the persona, and are audited (docs/api.md).
- **New system services, under the persona:** `$CRELNM`, `$DELLNM`, and `$GETJPI`
  (the persona's current privileges, for the SYSNAM check). In-process, as every
  other change: no helper process.
- **OpenVMS decides who may change what.** The probe (`probes/probe_crelnm.c`) showed
  that it checks the persona, not the process: STEWARD_TEST's persona got NOPRIV from
  a process holding every privilege. Steward grants nothing: the privileges are the
  ones the user switched on (D9).
- **What Steward refuses that OpenVMS would quietly change.**
  - Without SYSNAM, OpenVMS makes a supervisor or executive request a user-mode one,
    replacing a user-mode name nobody named. Steward refuses those modes without
    SYSNAM (403 NOSYSNAM) before calling. Kernel mode is always refused.
  - A define over an existing name at that mode is a 409 unless the request says
    `replace`. The browser shows the current value first.
  - What OpenVMS does by design is let through, but named first in the browser:
    `no_alias` removes the name at outer modes, and a deassign removes the outer modes
    too.
- **Tables:** as for reading. Never a process or job table (the service's), never the
  directory, `LNM$GROUP` named explicitly as the viewer's group table (under a persona
  it is the service's), and nothing the service's process directory also names
  (`$CRELNM` and `$DELLNM` look there first).
- **Accepted: the table is resolved twice** (Phase 7b review). Steward checks the
  table in LNM$SYSTEM_DIRECTORY, and `$CRELNM` or `$DELLNM` then resolves the name
  again. Someone who can rewrite LNM$SYSTEM_DIRECTORY between the two (SYSNAM or
  system access) could point the change at the pool's own process table. That person
  can already read the gateway file and every session record, so nothing new is
  reachable. The process-table refusal is absolute against the request's input, not
  against such a person.
- **Input:** the name and each equivalence are 1 to 255 printable ASCII characters,
  1 to 16 equivalences, attributes from fixed lists; the body is parsed in core
  (`st_lnm_def_parse`, unit tested) and anything unknown is refused.
- **The audit log** records the table, the name, the mode and OpenVMS's answer, never
  the equivalences: logical names sometimes hold passwords or connection strings.
- **A change to the system, made as the user.** A viewer with SYSNAM, GRPNAM or SYSPRV
  can now define names from the browser that they could define at a terminal,
  including names other processes translate. Probing which of Steward's own
  translations such a name could take over found one: the D14 helper's path (audit
  record, 2026-10-13), now resolved to a physical device at start-up. What remains is
  the service's own context when it starts (outer-mode system names, which need
  SYSPRV, and names in the service account's group table): keep that account in a
  UIC group of its own.

## Phase 8 additions (processes, read-only; D16)

- **New endpoints:** `GET api/v1/processes` and `GET api/v1/processes/{pid}` (api.md).
  They need a session, run under the persona, and change nothing.
- **New system services, under the persona:** `$GETJPI` (wildcard and by PID) and
  `$IDTOASC` for the rights list. In-process: no helper.
- **OpenVMS decides who sees what.** The probe (`probes/probe_jpi.c`) showed `$GETJPI`
  checks the persona, not the process: STEWARD_TEST's persona saw only its own
  process from a process holding every privilege, STEWARD_ADM's saw group 362 with
  GROUP and all 42 with WORLD.
- **The serving process is never shown.** Under the persona `$GETJPI` reports it with
  the viewer's username and UIC; it is left out of the list and refused by PID (404),
  so no viewer sees Steward's process presented as theirs.
- **Refusals as OpenVMS gives them.** NOPRIV (403) for a process the viewer may not see
  and NONEXPR (404) for none: whether a PID exists is told, as `SHOW PROCESS/ID=` tells
  it at a terminal.
- **New data shown:** process names, images, terminals, privileges, rights and quotas
  of processes the viewer may already see at a terminal. Process names and image
  names are set by their owners and reach the page only through the JSON writer and
  `dom.js`.
- **Steward's own pool is visible** to anyone with GROUP in the service account's
  group, or WORLD, as at a terminal. On x86 that group is shared with the test
  accounts; README.VMS advises a group of its own.
- **Stopping (8b):** `DELETE api/v1/processes/{pid}` is `$DELPRC` under the persona,
  with CSRF, audited. The probe (`probes/probe_delprc.c`) showed OpenVMS checks the
  persona: NOPRIV from an all-privileged process without GROUP. Steward refuses (409)
  any process of the service account, whatever the viewer holds: stopping the pool
  from the browser would cut the browser off, and a viewer with GROUP in a shared
  group, or WORLD, could otherwise do it. The serving process is NONEXPR to the stop
  as to the read. Nothing else is refused: system processes are stoppable by whoever
  OpenVMS allows, as at a terminal, and the browser names them as such and asks for
  the process name to be typed.
  - **Steward's own** means the service account's processes *and* any process running
    Steward's image: a worker busy with a request is reported under the requester's
    name (NOTES.md), but its image is Steward's.
  - **System processes** (UIC group up to MAXSYSGROUP) are refused too, whatever the
    viewer holds: in the browser check OpenVMS let STEWARD_ADM with WORLD stop OPCOM.
  - **Not refused:** other processes the page depends on, lighttpd among them. Whoever
    OpenVMS lets stop them can, as at a terminal.
  - **The typed name is the browser's check only.** The request carries the PID; CSRF
    keeps it to pages Steward served.

## Phase 9 additions (queues, read-only; D17)

- **New endpoints:** `GET api/v1/queues`, `GET api/v1/queues/{name}`, `GET
  api/v1/jobs/{entry}` (api.md). Session, persona, read-only.
- **New system service, under the persona:** `$GETQUI`. It asks the queue manager,
  another process; the probe (`probes/probe_qui.c`) showed it judges the persona, not
  the asking process: from an all-privileged process, STEWARD_TEST's persona got other
  users' jobs as inaccessible.
- **Shown as OpenVMS shows it.** An inaccessible job is listed by entry and status only
  (name, username and times withheld by the platform even if the queue manager
  returned them), and refused by entry (403), as `SHOW QUEUE/ALL` and `SHOW ENTRY` do.
- **Input:** queue names without wildcards (`$GETQUI` would take them as a search),
  entry numbers of 1 to 9 digits; walks bounded (an empty queue answers NOSUCHJOB, which
  ends the walk: a probe once looped on it).
- **Changes (9b):** hold, release and delete a job, stop and start a queue, by
  `$SNDJBC` under the persona, with CSRF, audited. The probe (`probes/probe_sndjbc.c`)
  showed the queue manager judges the persona: JBC NOPRIV from an all-privileged
  process; the group may read a job but not change it. Steward refuses (409), before
  the queue manager is asked and whatever the viewer holds, to stop SYS$BATCH, what it
  names in the system table, and the queues it feeds: the pool is started at boot by a
  job there (the user's choice, after OPCOM). If Steward cannot tell which queues those
  are, it refuses every stop (503) rather than guess. Starting is never refused.
- **New data shown:** queue names, descriptions and states (public to every user at a
  terminal), and the names, owners and files of jobs the viewer may read. Job and file
  names are set by their owners and reach the page only through the JSON writer and
  `dom.js`.

## Phase 5: load run and review (2026-10-11)

- **Load run, Linux** (`tests/load/load.py fcgi`). There were 8 concurrent clients, each
  signed in, going round every read-only endpoint with a privilege switch, plus
  hostile requests: no session, a forged cookie, no CSRF, a foreign Origin, malformed,
  long and over-limit bodies, NUL and traversal in paths, and bad parameters.
  - Three minutes under ASan/UBSan: 243,065 requests, every status as expected, no
    sanitizer report.
  - Three minutes on the plain build: 353,552 requests, resident memory flat (7.7 MB
    after warm-up, 7.2 MB at the end).
- **Soak, OpenVMS** (`API_PROBE_SOAK=n`: the real dispatcher, personas and files,
  without lighttpd). It ran 2,000 requests each as STEWARD_ADM with SYSPRV and as
  STEWARD_TEST with none, then 10,000 as STEWARD_ADM. Page-file use and the open-file
  quota were the same after the first round and at the end, and no persona was left
  active.
- **Load through lighttpd** (`tests/load/load.py http`): 4 clients for 2 minutes as
  STEWARD_TEST, 3,772 requests, every status as expected (PHASE5.md).
- **Review:** the Phase 6 code was reviewed line by line against the checklist below;
  findings are in the audit record. An independent review (`/security-review`) and the
  external review and penetration test (`REVIEW-BRIEF.md`) remain the user's to run.

## What runs, and when

**Every push (CI, `.github/workflows/ci.yml`) and `make audit` locally:**
- GCC `-fanalyzer` over every source file, warnings as errors.
- cppcheck (warning and portability classes) and flawfinder (level 4 and up).
- Semgrep with the C, JavaScript and secrets rule packs; gitleaks over the history.
- `tools/audit_rules.sh`: the project rules above, which no general tool knows.
- The unit tests and the API suite against ASan/UBSan builds, and 200,000 rounds of mutation fuzzing
  of the JSON and FastCGI parsers under ASan/UBSan.
- Strict compiler flags (`-std=c99 -pedantic -Wall -Wextra`), never weakened.

**At every phase exit (a gate: the phase does not close until it passes):**
1. Update this threat model for what the phase added: new endpoints, new system
   services, new data shown.
2. A line-by-line security review of every changed file against the checklist below,
   by someone other than the author of the change (for Claude-written code: the user,
   or an independent review run with `/security-review` and `/code-review`, with
   findings checked by hand).
3. The VMS-side checks no Linux tool can do: every LINK checked for `$SEVERITY`;
   image privileges and file protections listed and justified; the service
   account's privileges confirmed minimal (`SHOW PROCESS/PRIVILEGES` in the pool).
4. Findings recorded below with severity, fix commit and a regression test that
   fails without the fix.

**Before the first release (Phase 5):** an independent external review of the
authentication, session and persona code, and a penetration test of a staging
instance behind nginx proxy manager.

## Review checklist

- [ ] Every new input is bounded and validated before use (lengths, character sets,
      integer ranges), and refused rather than repaired.
- [ ] Every system-service call checks both the return status and the IOSB/ACMESB
      status. 64-bit masks are not truncated (`PRV$M_*` above bit 31).
- [ ] Every new handler path ends without assuming anything about persona state
      (the dispatcher ends it).
- [ ] No new error message tells an unauthenticated client which of several
      failures happened.
- [ ] Secrets are scrubbed with `st_zero` and never logged.
- [ ] Strings from OpenVMS reach the browser only through the JSON writer and
      `dom.js`.
- [ ] Item lists, descriptors and buffers are sized from the definitions, and every
      `retlen` is honoured.
- [ ] New dependencies: none without a decision in DECISIONS.md.
- [ ] Least-privilege claims are verified on the **success** path, run as the real
      service account (a failed sign-in never creates a persona: PHASE1.md).

## Audit record

| Date | Phase | Finding | Severity | Fix | Regression test |
|---|---|---|---|---|---|
| 2026-10-10 | 1 | Use-after-free: the malformed-login audit line read the username after the JSON document was freed and scrubbed | High (memory safety, pre-auth) | b99ac16 | API suite under ASan (`make api-test-asan`) |
| 2026-10-10 | 1 | `X-Forwarded-For` walk lost the hop after a trusted proxy, so a chain of proxies gave the wrong client address | Medium (intrusion records misattributed) | b99ac16 | unit `test_proxy` "a chain of trusted proxies", failed before the fix |
| 2026-10-10 | 1 | `make audit` ran `-fanalyzer` under `-fsyntax-only`, where it silently does nothing | Medium (audit gap) | this commit | planted double free is caught |
| 2026-10-10 | 1 | First CI run: flawfinder found 16 level-4 uses of `strcpy`/`strcat`/`sprintf` (each bounded in context, none exploitable as written) | Low (hardening) | this commit: `st_copy`/`st_append`/`snprintf`; the printf wrapper gets a GCC `format` attribute | CI flawfinder at level 4 |
| 2026-10-10 | 1 | cppcheck: four buffers filled by system services or RMS looked uninitialised to it | Informational | zero-initialised | CI cppcheck |
| 2026-10-10 | 1 | Phase 1 gate review: any local process could connect to the loopback FastCGI ports, bypass lighttpd and choose its own REMOTE_ADDR, guessing passwords without breakin evasion | High (local attacker) | gateway secret shared with lighttpd (this commit) | unit `test_gateway`, API suite, and on VMS a direct connection gets 403 |
| 2026-10-10 | 1 | Files created by the service took the account's default protection, including group read | Low (already behind a no-group directory) | pool sets `(S:RWED,O:RWED,G,W)` as the default | phase-exit listing |
| 2026-10-10 | 1 | API responses had no CSP of their own | Informational (hardening) | `default-src 'none'; frame-ancestors 'none'` on every API response | API suite |
| 2026-10-10 | 1 | Claimed "IMPERSONATE alone suffices" from a failed-sign-in test; the first successful sign-in failed: `$PERSONA_CREATE` needs GRPPRV/SYSPRV to read the user's UAF record | Process (false verification) | correction in PHASE1.md; D2 to be amended | checklist item: verify the success path as the real account |
| 2026-10-10 | 1 | Privilege masks above bit 31 truncated to 0 make `$SETPRV` a silent no-op that returns NORMAL (probe code) | Recorded as a rule | PHASE1.md | checklist item |
| 2026-10-10 | 1 | Pool started with `RUN/DETACHED LOGINOUT` without `/AUTHORIZE`: the processes took the batch job's privileges, not the UAF's, so the authorized SYSPRV never reached them (fail-safe: persona creation failed) | Informational (deployment) | fe2aa18 | phase-exit check of `F$GETJPI(pid,"AUTHPRIV")` |
| 2026-10-10 | 1 | Phase exit: review of the SYSPRV bracket and the pool change; browser checks of sign-in, D9, sign-out, DISUSER and expired passwords | None | | PHASE1.md "Phase exit checks" |
| 2026-10-10 | 2 | A query parameter too long for its buffer, or badly encoded, was treated as absent, so `?filter=<80 chars>` listed every user instead of being refused | Low (no access gained: OpenVMS still decides; violates "refuse, don't repair") | Phase 2 commit (`svc_query`) | unit "an over-long filter is refused", "a badly encoded filter is refused" |
| 2026-10-10 | 2 | `users/{u}/identifiers` fetched the UIC with `$GETUAI`, which made Steward stricter than OpenVMS for unprivileged users | Informational (functional; D10) | Phase 2 commit: UIC from `$ASCTOID` | unit "including another user's identifiers"; on VMS as STEWARD_TEST |
| 2026-10-10 | 2 | UAF times are local; read as UTC, they were an hour late on a BST node | Informational (correctness) | Phase 2 commit | PHASE2.md AUTHORIZE comparison |
| 2026-10-11 | 3 | Use-after-free: `svc_user_set_password` quoted a JSON key in its error after freeing the document (the Phase 1 bug class again; `-fanalyzer` missed it) | Medium (memory safety, signed-in) | Phase 3 API commit | `make test-asan` (new: unit tests under ASan, part of `make audit`), "unknown members are refused" |
| 2026-10-11 | 3 | A test's header list was unterminated: harmless on Linux by luck, fatal on OpenVMS. The unit tests ran without sanitizers, so nothing caught it | Process (audit gap) | `make test-asan` | the reintroduced bug is caught |
| 2026-10-11 | 3 | Design: CHANGE_PASSWORD charges failures to the account, so a public change endpoint would let anyone lock accounts | High if built naively; found by probe before any code | D11 | unit "wrong current password looks like a failed sign-in" |
| 2026-10-11 | 4 | A home directory requested for an account with no default device (DEFAULT has only `[USER]`) was created relative to the serving process's default disk. The live test put `[STEWARD_NEW]` on the work disk; it was found and removed | Medium (writes in the wrong place, owned by the new UIC) | Phase 4 commit: no directory without a device, with a warning; the UI prefills a device | unit "no directory without a default device"; `phase4_live.py` |
| 2026-10-11 | 6 | CI's no-node-details rule failed on two pushes: a probe comment and PHASE6.md quoted the client's private address. The pushes went out before `make audit` was run locally | Low (a LAN address in two commits' history) | 8c5b49c: documentation addresses | `audit_rules.sh no-node-details` (CI) |
| 2026-10-11 | 6 | `atoll` used in a unit test is undeclared in VSI C under C99, so it would return `int` | Informational (test only) | Phase 5 commit: `strtoll` | VSI C `IMPLICITFUNC` informational at build |
| 2026-10-11 | 5 | Phase 5 review of access history: when 6,000 process records were held, each new one scanned them all for the oldest, so a busy accounting file made a request quadratic | Low (slow responses; needs SYSPRV or READALL to reach) | Phase 5 commit: a ring | 10,000-request soak on the node |
| 2026-10-11 | 5 | Phase 5 review: one accounting or journal record longer than the buffer (8 KB for the journal) ended the read of the whole file (`RMS-W-RTB`), silently hiding everything after it | Low (incomplete history) | Phase 5 commit: 64 KB buffers, an over-long record is skipped | code review; no such record on the node |
| 2026-10-11 | 5 | Phase 5 review: the SSH log search left RMS's wildcard context open when it stopped early (a refusal, or 256 logs) | Informational (no channel leak measured) | Phase 5 commit: the search is ended on every exit | soak: open-file quota unchanged |
| 2026-10-11 | 7 | The SHOW LOGICAL parser could read past the end of a line. The fuzzer found it once each line had a buffer of exactly its length (the shape of the line was not recorded) | Medium (memory safety, signed-in; the input is the viewer's own listing) | ff48318 | fuzz target with exact-length lines |
| 2026-10-13 | 7 | `logicals/LNM$SYSTEM_DIRECTORY/{name}` translated in the directory, which has the table attribute; the stub refused it | Informational (consistency; no access gained: nothing went through the process table) | 2505c0f | `phase7_live.py` "a single-name lookup only in a real table" |
| 2026-10-13 | 7 | Phase 7 review: `st_valid_lnm_table` refused `LNM$JOB` but not a job table by its own name, which `GET logicals/tables` lists (the pool's own among them). A single-name lookup in it ran `$TRNLNM` under the persona in the service's job table. Whether OpenVMS's protection check stops an unprivileged viewer there was not probed; the table holds SYS$LOGIN and the like, and the settings (the gateway secret) are process names | Low (unverified exposure of the service's job names) | this commit: every `LNM$JOB_` table refused | unit "a job table by its own name is refused"; `phase7_live.py` "a job table by its own name", "one name in a job table" |
| 2026-10-13 | 7 | Phase 7 review: the helper procedure's path could be overridden by `getenv("STEWARD_LNM_HELPER")`, which nothing in the kit defined. On VMS `getenv` also translates logical names through the service's group and system tables, so anyone with GRPNAM in the service account's group, or SYSNAM, could have made every viewer's listing run their own procedure, as that viewer and with their privileges switched on | Medium (code execution as other users; needs GRPNAM or SYSNAM) | this commit: the path is fixed; only `api_probe` can swap it (`st_plat_vms_test_helper`) | `audit_rules.sh lnm-helper-test-only`; `env-only-in-main` now covers `src/plat` |
| 2026-10-13 | 7 | Phase 7 review: the 30 s deadline was noticed only when the reply read had not completed. A helper whose login procedure kept the reply mailbox full, never sending `%%END%%`, held the pool process for ever. `$SETIMR`, `$GETDVIW` and the request writes' IOSBs were also unchecked | Medium (availability: a few requests pin every pool process; any signed-in user) | this commit: the timer is checked after every wake, at most 100,000 messages per listing, every status checked | `phase7_live.py` with `PHASE7_FAILDIR`: `probes/lnm_flood.com` stopped at 30 s on the node |
| 2026-10-13 | 7 | Phase 7 review: a helper that died without answering (a refused login, a LOGIN.COM that logs out) cost the full 30 s | Low (availability) | this commit: a termination mailbox; the error carries the helper's final status | `probes/lnm_dead.com`: an error in 3 s on the node |
| 2026-10-13 | 7 | Phase 7 review: the viewer's global symbols reached `STEWARD_LNM.COM` (a global `DIRECTORY ==` replaced the verb, probe), and a READ error left the checks spinning until the deadline | Low (the viewer's own listing only) | this commit: `SET SYMBOL/SCOPE=(NOLOCAL,NOGLOBAL)`, `/ERROR=` on the OPEN and READs. A global symbol named `SET` would still act before the scope line | `probes/lnm_scope.com` |
| 2026-10-13 | 7 | Phase 7 review: `st_plat_lnm_get` checked the table in LNM$SYSTEM_DIRECTORY but `$TRNLNM` resolves the table name through LNM$PROCESS_DIRECTORY first | Informational (only the service's own login could define such a name) | this commit: refused unless `$TRNLNM` reports the checked table | `phase7_live.py` (every lookup) |
| 2026-10-13 | 7 | Phase 7b probe (`probes/lnm_shadow.py`): the helper process translates `STEWARD$ROOT:[COM]STEWARD_LNM.COM` itself, as the viewer, and a user- or supervisor-mode `STEWARD$ROOT` in the viewer's group table took over. Anyone able to write a group table (GRPNAM, or GRPPRV in that group) could make another member's listing run their procedure as that member, with the privileges the member switched on. Present since 7a (0.5.0) | Medium (code execution as another group member; needs GRPNAM or GRPPRV) | this commit: the path is resolved at start-up, as the service, to `_DEV:[dir]` (NOCONCEAL, FULLDEVNAM); without it, listing is refused | `lnm_shadow.py` after: the viewer-group decoys ignored; `phase7_live.py` 20 ok |
| 2026-10-15 | 8 | Phase 8b live test: `api_probe` takes the work account for the service account, so its "Steward's own processes" guard did not cover the real pool, and the test's deliberate request to stop `STEWARD_19300` stopped it. The production guard (the pool runs as STEWARD) was not affected | Operational (one pool process down a few minutes on x86; caused by the test, not reachable by a user) | this commit: the test names a test account as "own" and never a pool process; the probe's setter is test-only (audit rule) | `phase8b_live.py` 8 ok with the pool's PIDs unchanged |
| 2026-10-15 | 8 | Phase 8 review: a pool worker busy with a request holds the requester's persona, and `$GETJPI` reports it under their username and UIC (shown by `probes/probe_hold.c`; access still follows its real owner). So the service-account guard did not cover a busy worker: anyone with WORLD, or GROUP in the service account's group, could stop it | Medium (availability: busy pool workers stoppable by users with WORLD or GROUP there) | this commit: a stop also refuses any process running Steward's own image (recorded at start-up), usernames compared without case | `phase8b_live.py`: a process holding STEWARD_TEST's persona, its image named as Steward's, refused with WORLD and still running |
| 2026-10-15 | 8 | Phase 8 review: `st_parse_pid` took `FFFFFFFF`, which `$GETJPI` treats as the wildcard, so a read or stop could describe or audit another process | Low | this commit: FFFFFFFF refused, and both handlers check the process found is the one asked for | unit "FFFFFFFF refused" |
| 2026-10-15 | 8 | Phase 8b browser check: STEWARD_ADM with WORLD stopped OPCOM through Steward. D16 refused only Steward's own processes; OpenVMS allowed it | Medium (availability of a system service; needs WORLD) | this commit: system processes (UIC group up to MAXSYSGROUP) refused whatever the viewer holds; the page offers no Stop on them. OPCOM restarted by the user | unit "OPCOM refused with WORLD"; `phase8b_live.py` (a test job counted as system via `API_PROBE_MAX_SYS_GROUP`, never a real one) |
| 2026-10-15 | 7 | Phase 7 review leftovers: the helper's process name `STW<request>_<reply>` could be created ahead by a member of the viewer's group (process names are unique in a group), making the group's listings fail; and a listing over 4 MB answered 500 | Low (availability of listings for one group; a large table) | this commit: the name carries a random part and is retried on a clash; listings stop at 3.5 MB with `truncated` | `phase7_live.py` 22 ok with the new procedure |
| 2026-10-15 | 9 | Phase 9 review: the start-up-queue guard failed open. If `$GETQUI` could not read SYS$BATCH's generic targets (queue manager busy, an odd status), only SYS$BATCH was guarded and its execution queues could be stopped; more than 6 targets, or a list over 1,023 bytes, also slipped through; and a SYS$BATCH logical naming another was followed one level only | Medium (Steward's pool would not start at the next boot; needs SYSPRV or OPER) | this commit: fails closed (503, every stop refused when the start-up queues cannot be told), up to 32 names or "cannot tell", logical names followed 9 levels; the target list is parsed in core (commas, spaces or NULs), unit tested | unit "start-up queues unknown: every stop refused"; target-list checks; `phase9b_live.py` 14 ok |
