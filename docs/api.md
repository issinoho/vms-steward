# Steward REST API, v1

All paths are relative to the site root, which may be a reverse-proxy prefix (D7).
Requests and responses are JSON (`application/json; charset=utf-8`). Strings from
OpenVMS are ISO-8859-1 there and UTF-8 here. A character above U+00FF in a request
is refused rather than mangled.

## Conventions

- **Authentication:** `POST api/v1/session` sets the session cookie `steward_session`
  (`HttpOnly; SameSite=Strict; Secure`, path `<prefix>/api`). Every other endpoint needs
  it, unless marked *public*.
- **CSRF:** every request other than GET or HEAD must send `X-Steward-CSRF` with the
  token from the sign-in response or from `GET api/v1/session`. State-changing requests
  must also be same-origin (`Origin` / `Sec-Fetch-Site`).
- **Runs as you:** each request runs under the caller's OpenVMS persona, so OpenVMS
  decides what is allowed (D2). A refusal comes back as 403 with the OpenVMS message.
- **Errors** are RFC 9457 problem details (`application/problem+json`):

  ```json
  {"type": "/api/v1/problems/no-privilege", "title": "Not permitted by OpenVMS",
   "status": 403, "vms_status": "%X000028E4",
   "vms_message": "%SYSTEM-F-NOSYSPRV, operation requires SYSPRV privilege"}
  ```

  `type` ends in a stable slug for programs. `vms_status` and `vms_message` appear when
  OpenVMS refused something.
- **Every response** is `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.
- Requests must reach Steward through its lighttpd, which adds the gateway secret.
  Anything else gets 403.

## Endpoints (Phase 1)

### `GET api/v1/health` (public)

`200 {"status":"ok"}`. For load balancers and the pool's own checks.

### `POST api/v1/session` (public): sign in

```json
{"username": "steward_test", "password": "..."}
```

Usernames are case-insensitive, 1-12 characters from `A-Z 0-9 _ $`. The password is
checked by `SYS$ACM`, so the system's own policy applies: expiry, DISUSER, login
hours, intrusion detection.

| Status | Slug | When |
|---|---|---|
| 201 | | signed in; body below, cookie set |
| 400 | `bad-json`, `bad-request` | malformed body, or missing fields |
| 401 | `sign-in-failed` | wrong password, no such user, disabled, malformed username, or under breakin evasion. All look the same on purpose |
| 403 | `password-expired` | the password was right but has expired (no session is created) |
| 403 | `cross-origin` | the request came from another origin |
| 503 | `auth-unavailable` | `$ACM` itself failed |

```json
{"username": "STEWARD_TEST", "csrf": "<64 hex>", "idle_timeout": 900,
 "expires_at": 1791763200}
```

### `GET api/v1/session`: who am I

```json
{"username": "STEWARD_TEST", "owner": "steward probe", "account": "",
 "uic": "[362,1]",
 "authorized_privileges": ["TMPMBX", "NETMBX", "GRPPRV"],
 "current_privileges": ["TMPMBX", "NETMBX"],
 "identifiers": [],
 "csrf": "<64 hex>", "idle_timeout": 900, "expires_at": 1791763200}
```

`401 not-signed-in` or `session-expired` when there is no live session.

### `PUT api/v1/session/privileges`: switch authorized privileges on or off (D9)

```json
{"enabled": ["SYSPRV", "GRPPRV"]}
```

This replaces the set of privileges switched on for this session, on top of your
defaults, like `SET PROCESS/PRIVILEGE`. `[]` goes back to the defaults. The set takes
effect at once, stays for the session's later requests, and each change is audited.
Names are case-insensitive, and `DETACH` is accepted for IMPERSONATE.

| Status | Slug | When |
|---|---|---|
| 200 | | the updated whoami, as `GET api/v1/session` |
| 400 | `bad-request` | `enabled` missing or not a list |
| 403 | `not-authorized` | a privilege you are not authorized for; `detail` names it |
| 422 | `unknown-privilege` | not an OpenVMS privilege name |

`GET api/v1/session` reports `default_privileges`, `enabled_privileges` (this set)
and `current_privileges` (what is in effect: defaults plus enabled).

### `DELETE api/v1/session`: sign out

`204`; the session is deleted and the cookie cleared.

## The dashboard: `GET api/v1/system`

The system at a glance, with the figures vms-fastfetch shows, read as you:

```json
{"node": "X86VMS",
 "os": {"name": "OpenVMS", "version": "E9.2-4", "arch": "x86_64"},
 "hardware": {"model": "QEMU Standard PC (Q35 + ICH9, 2009)", "virtual_machine": true},
 "boot_time": 1791637646,
 "cpu": {"active": 2, "available": 2, "idle_ticks": 9101752, "sampled_at_ms": 1791708994130,
         "load": {"current": 1, "computable": 0, "computable_outswapped": 0}},
 "memory": {"total": 7620722688, "free": 4875476992, "modified": 70426624, "in_use": 2674819072},
 "paging": {"total": 2447310848, "used": 0},
 "disks": [{"device": "DKA0:", "label": "X86SYS", "logical_volume": "DISK$X86SYS",
            "filesystem": "ODS-5", "total": 23040000000, "free": 1237032960, "system_disk": true}],
 "processes": {"count": 1, "hidden": 41, "interactive": [{"username": "SYSTEM", "sessions": 1}]},
 "queues": {"count": 4, "batch": 2, "output": 2, "stopped": 0,
            "jobs": {"executing": 1, "pending": 0, "holding": 0, "timed": 2}},
 "cluster": {"member": false}}
```

- Sizes are bytes; `boot_time` is seconds since 1970 (UTC).
- **CPU usage** is not sampled by the server, which would hold a pool process for the
  interval. `idle_ticks` counts idle ticks over all CPUs, 100 a second per CPU, and
  `sampled_at_ms` says when it was read. Between two responses:
  `busy% = 100 × (1 − Δidle_ticks ÷ (Δseconds × 100 × active))`.
- **`load`** gives process states now. OpenVMS keeps no load averages.
- **Processes** are those your persona may see. `hidden` counts the rest: without
  GROUP or WORLD, OpenVMS shows you only your own.
- **Background polls:** a request with `X-Steward-Background: 1` is served normally but
  does not count as activity for the idle timeout. The dashboard's refreshes send it,
  so a dashboard left open still signs out when idle.

## Endpoints (Phase 2): users and rights identifiers, read-only

Every call runs as you, so OpenVMS decides what you may read (D10, docs/PHASE2.md):

| | Needs, as OpenVMS enforces it |
|---|---|
| list users | SYSPRV or READALL (SYSUAF is not group- or world-readable) |
| one user | your own: nothing; your UIC group's: GRPPRV; anyone's: SYSPRV |
| identifiers, holders, identifiers held | nothing |

A refusal is `403 no-privilege` with the OpenVMS message, e.g.
`%SYSTEM-F-NOSYSPRV` or `%RMS-E-PRV`.

**Lists** take `filter`, `after` and `limit` (1-200, default 50). With `*` or `%` the
filter is a DCL wildcard on the name; without them it matches any part of the name
or, for users, the owner. It is case-insensitive, up to 31 printable characters,
with no quotes or backslashes. A list ends with `"next"`: pass it back as `after`
for the next page, and `null` means there are no more.

Times are seconds since 1970 (UTC), or `null` for none or never. Flags and
attributes use AUTHORIZE's names.

### `GET api/v1/users?filter=&after=&limit=`

```json
{"users": [{"username": "STEWARD_TEST", "owner": "steward probe", "account": "",
            "uic": "[362,1]", "flags": [], "expiration": null,
            "last_login_interactive": 1791671460, "last_login_noninteractive": null}],
 "next": null}
```

The list is in SYSUAF order (alphabetical). If a record in it cannot be read as you,
the row is `{"username": "X", "restricted": true}`.

### `GET api/v1/users/{username}`

The list fields plus:
- `cli`, `clitables`, `default_device`, `default_directory`, `lgicmd`;
- `password`: `pre_expired`, `changed`, `secondary_changed`, `lifetime_days` (null
  for none), `minimum_length`, `login_failures`;
- `secondary_days`, e.g. `["SAT","SUN"]`;
- `restricted_hours`: for each of `network`, `batch`, `local`, `dialup` and
  `remote`, the `primary` and `secondary` hours (0-23) with **no** access;
- `authorized_privileges` and `default_privileges`;
- `quotas`: `prio`, `queprio`, `maxjobs`, `maxacctjobs`, `maxdetach`, `prclm`, `biolm`,
  `diolm`, `astlm`, `tqelm`, `enqlm`, `fillm`, `shrfillm`, `bytlm`, `pbytlm`,
  `jtquota`, `wsdef`, `wsquo`, `wsextent`, `pgflquo`, and `cpu` (10 ms ticks, 0
  for none).

404 `not-found` with `%RMS-E-RNF` if there is no such user, whoever asks
(docs/PHASE2.md, finding 2).

### `GET api/v1/users/{username}/identifiers`

```json
{"username": "APACHE$WWW",
 "identifiers": [{"name": "APACHE$READ", "value": "%X80010009", "attributes": []}]}
```

`attributes` are those of the holding.

### `GET api/v1/identifiers?type=general|uic|all&filter=&after=&limit=`

```json
{"identifiers": [{"name": "BATCH", "value": "%X80000001", "type": "general",
                  "attributes": []}], "next": null}
```

Sorted by name, as AUTHORIZE lists them. `type` defaults to `general`. A UIC
identifier's value is `[g,m]` in octal. Past 8192 matches the response adds
`"truncated": true`.

### `GET api/v1/identifiers/{name}`

One identifier, in the same form as a list entry.

### `GET api/v1/identifiers/{name}/holders`

```json
{"name": "APACHE$READ",
 "holders": [{"username": "APACHE$WWW", "uic": "[200,1]", "attributes": []}]}
```

`username` is the holder's UIC identifier, which is normally the username. It is
`null` if the UIC has none.

## Endpoints (Phase 3): changes

Each change runs as you, so OpenVMS decides (D2): changing a UAF record needs
SYSPRV (or GRPPRV for another member of your group), and changing the rights database
needs SYSPRV. Without them the answer is `403` with the OpenVMS message, e.g.
`%SYSTEM-F-NOPRIV` or `%RMS-E-PRV`. All of these need the CSRF header, and every
change is audited, never with a password.

Bad input is `422 invalid-value`, with a `detail` naming the field. Unknown members
are refused, not ignored.

### `PATCH api/v1/users/{username}`, with `If-Match: <ETag>`

The `ETag` comes from `GET api/v1/users/{username}`, as a header and as `etag` in
the body. Without it the answer is `428 precondition-required`. If the record has
changed since, it is `412 changed`, with the current `ETag`.

Members, all optional:
- `owner` (≤31), `account` (≤8), `cli`, `clitables`, `default_device` (≤31 each),
  `default_directory`, `lgicmd` (≤63 each). Printable characters only; the device,
  directory, CLI, tables and account may not contain spaces.
- `flags`, `secondary_days`, `authorized_privileges`, `default_privileges`: lists
  that replace the whole set.
- `expiration`: seconds since 1970 (UTC), or `null` for none.
- `password`: `{"lifetime_days": 1-9999 | null, "minimum_length": 0-32}`.
- `restricted_hours`: `{"batch": {"primary": [0, 1], "secondary": []}, ...}`; the
  kinds of login you leave out are unchanged.
- `quotas`: `{"prio": 0-31, "queprio": 0-255, the others 0-65535 or 0-4294967295 by
  their size}`.

`200`: the record as it now is, with its new ETag.

### `POST api/v1/users/{username}/password`

```json
{"password": "...", "pre_expired": true}
```

An administrator sets a password. OpenVMS hashes it, applies the account's minimum
length (`422` with `%SYSTEM-F-INVPWDLEN` if it is too short), and sets the password
date to now. `pre_expired` marks it expired, as AUTHORIZE `/PWDEXPIRED` does. `204`.

### `POST api/v1/session/password` (public): change your own password

```json
{"username": "STEWARD_TEST", "current": "...", "new": "..."}
```

This works signed in or not, which includes a user whose password has expired (sign
in gives `403 password-expired`). The current password is checked first, as at sign
in (D11):
- `401 sign-in-failed`: a wrong username or current password, indistinguishable, as
  at sign in;
- `422 password-refused`: the current password was right, but OpenVMS refused the
  new one (too short, in the history list or the dictionary), with its message;
- `204`: changed.

### `POST api/v1/users/{username}/identifiers`: grant

```json
{"name": "STEWARD_OPS", "attributes": ["RESOURCE"]}
```

A holding can have only attributes its identifier has; anything else is refused
(`422`), because OpenVMS would accept it and drop it silently (PHASE3.md). Granting
one already held is `409` (`%SYSTEM-F-DUPIDENT`). `201`, with the user's
identifiers.

### `PUT api/v1/users/{username}/identifiers/{name}`

```json
{"attributes": []}
```

Sets a holding's attributes. `200`, with the user's identifiers.

### `DELETE api/v1/users/{username}/identifiers/{name}`: revoke

`204`. `404` (`%SYSTEM-F-NOSUCHID`) if it is not held.

### `POST api/v1/identifiers`

```json
{"name": "PROJECT_X", "value": "%X80010099", "attributes": ["RESOURCE"]}
```

`value` is optional; without it OpenVMS chooses the next free one. A value must have
the top bit set (a general identifier). A name already in use is `409`. `201`, with
the identifier.

### `PATCH api/v1/identifiers/{name}`

```json
{"name": "NEW_NAME", "attributes": ["NOACCESS"]}
```

Rename it, or replace its attributes, or both. Clearing an attribute here also clears
it on every holding. `200`, with the identifier.

### `DELETE api/v1/identifiers/{name}`

`204`. OpenVMS removes the holdings with it, as AUTHORIZE does.

UIC identifiers belong to accounts and cannot be granted, renamed or deleted
through these endpoints (`422 uic-identifier`). Creating and deleting users is
Phase 4.

## Endpoints (Phase 4): create, copy and delete users (D6)

As AUTHORIZE ADD, COPY and REMOVE, under your persona: OpenVMS requires SYSPRV
(write access to SYSUAF).

### `POST api/v1/users`

```json
{"username": "JSMITH", "uic": "[362,10]", "password": "...", "template": "DEFAULT",
 "pre_expired": true, "copy_identifiers": false, "create_directory": false,
 "owner": "J Smith", "default_device": "USERS:", "default_directory": "[JSMITH]",
 "flags": []}
```

- `username`, `uic` (octal `[g,m]`; group 1–37776, member 0–177776) and `password` are
  required.
- `template` defaults to `DEFAULT`, which is AUTHORIZE ADD. Any other user makes it a
  copy, as AUTHORIZE COPY: every setting of that user, including its directory.
- `copy_identifiers` also grants the template user's identifiers. AUTHORIZE COPY does
  not, so it defaults to false.
- Any member PATCH accepts is applied over the template's values. DEFAULT carries
  DISUSER, so send `"flags": []` (or the list without DISUSER) for an account that
  can log in.
- `pre_expired` defaults to true.
- `create_directory` makes the default directory, owned by the new account, on the
  account's default device. If the account has no default device (DEFAULT has none),
  no directory is made and the response says so in `X-Steward-Warning`.

`201` with the new account's record, its UIC identifier added. Refusals:
- `409` if the username, an identifier of that name, or the UIC is already in use;
- `422` if OpenVMS refuses the password (`INVPWDLEN`, `PWDSYNTAX`, …).

If anything fails after the record was written, Steward undoes the record and the
identifier, so nothing is left behind.

### `DELETE api/v1/users/{username}`, with `If-Match: <ETag>`

As AUTHORIZE REMOVE: the record, its UIC identifier and its identifier holdings. Files
and directories are not touched. `204`. `428` without If-Match; `412` if the account
changed since you read it. `409` for the account you are signed in as, or the
service's own.

### `GET api/v1/uic/next?group=362`

`{"uic": "[362,4]"}`: the lowest free member of the group, from the rights
database's UIC identifiers. A suggestion: the create still refuses a UIC in use.

## Access history (Phase 6, D13): `GET api/v1/access`

`?since=&until=&user=&route=&outcome=&limit=`

Who reached the system, when, from where and by which route, merged from the system's
own records and read **as you**. A source OpenVMS will not let you read is reported,
not hidden, and the others are still shown. A source read but not to the end has
`"complete": false`: OpenSSH's logs are looked up by name for the connections
accounting gives, and searched for the rest (live connections, or all of them when
accounting is refused) only for a few seconds, since `SSH$ROOT:[VAR]` can hold tens of
thousands. Connections whose log was not reached show without their sign-in method.

```json
{"since": 1791651600, "until": 1791738000,
 "sources": {"accounting": {"read": true}, "audit": {"read": true}, "ssh": {"read": true},
             "steward": {"read": false, "vms_status": "%X0001829A",
                         "vms_message": "%RMS-E-PRV, insufficient privilege or file protection violation"},
             "live": {"read": true}},
 "events": [
   {"start": 1791737990, "end": null, "kind": "connected", "source": "live", "user": "SYSTEM",
    "route": "TELNET", "from": "198.51.100.45", "terminal": "TNA3:", "detail": "", "pid": "00008211"},
   {"start": 1791737510, "end": 1791737920, "kind": "session", "source": "accounting", "user": "IAIN",
    "route": "SSH", "from": "198.51.100.20", "terminal": "", "detail": "publickey ED25519", "pid": "000081F3"},
   {"start": 1791737400, "end": null, "kind": "failure", "source": "audit", "user": "STEWARD_TEST",
    "route": "SSH", "from": "198.51.100.20", "terminal": "_FTA581:",
    "detail": "%LOGIN-F-INVPWD, invalid password"}],
 "truncated": false}
```

- **Parameters.** `since` and `until` are seconds since 1970 (UTC); the default is the
  last 24 hours. `user` filters as the user list does (wildcards `*` and `%`, or a
  substring). `route` is one of the routes below, any case. `outcome` is `session`,
  `failure`, `breakin` or `connected`. `limit` is 1 to 2000 (default 500); past it,
  `truncated` is true. Events are newest first.
- **Kinds.** `connected`: still on now (from the live process list; `end` is null).
  `session`: a finished one (`end` set; null if no end was recorded). `failure`: a
  sign-in that was refused. `breakin`: OpenVMS's break-in detection fired.
- **Routes.** `SSH`, `TELNET` (TNA terminals), `DECnet` (RTA: SET HOST), `LAT`,
  `local` (console and other local terminals), `batch` (`detail` names the queue),
  `network` (a network process that is not SSH, such as DECnet or FTP), `Steward`.
- **Sources**, each read as you:

| Source | File | Gives |
|---|---|---|
| `accounting` | `ACCOUNTNG` (default `SYS$MANAGER:ACCOUNTNG.DAT`) | every finished process: interactive, network, batch; and LOGINOUT's failures |
| `audit` | `SYS$MANAGER:SECURITY.AUDIT$JOURNAL` | login failures and break-ins, including `$ACM` failures that never reach accounting |
| `ssh` | `SSH$ROOT:[VAR]*_*.LOG` (VSI OpenSSH) | the method, user and address of each SSH connection, while the logs last |
| `steward` | Steward's own audit log | sign-ins to Steward, with the browser's address |
| `live` | `$GETJPI` | who is on now: as at a terminal, without WORLD you see only your own processes |

  The files are protected from ordinary users, so a viewer needs SYSPRV or READALL
  switched on (D9) to read them. A refused source carries OpenVMS's status and message.
- **One connection, one event.** An SSH connection appears in accounting as the SSH
  server's network process under `SSH$SSH`. The user's session process and commands run
  beneath it, and its log is named after its PID. These are joined into one event:
  `pid` is the `SSH$SSH` process. A failure seen by the journal, the SSH log and
  LOGINOUT's accounting record is shown once, with the journal's time and status.
  Steward's own `$ACM` sign-in failures (remote user `STEWARD` in the journal) are taken
  from Steward's log instead, which has the browser's address rather than the proxy's.
- **An SSH connection's `detail`** says what it was (`session`: a shell or SFTP;
  `command`: `ssh host cmd`), the sign-in method when its log still exists, and the
  client's host name. Accounting names the client by host on the server's process and
  by address on the session's. Steward learns the pairs from connections that have
  both, so one client is always shown by its address.
- The page shows back-to-back sessions (same user, route and address, less than five
  minutes apart) as one row that opens to list them. The API returns every event.
- Times from OpenSSH's logs are the log file's creation and last-write dates: its lines
  carry none.

## Logical names (Phase 7, D14): read-only

Read **as you**: what you could not see with `SHOW LOGICAL` at a terminal, you do not
see here. The process and job tables, and the names that search them (`LNM$PROCESS`,
`LNM$PROCESS_TABLE`, `LNM$PROCESS_DIRECTORY`, `LNM$JOB`, `LNM$FILE_DEV`,
`LNM$DCL_LOGICAL`, `LNM$DIRECTORIES`, `LNM$TEMPORARY_MAILBOX`,
`LNM$PERMANENT_MAILBOX`), and every job table by its own name (`LNM$JOB_8217EDC0`),
are refused with `400`. Under a persona they would be the service's own, not yours,
and one of the job tables is the service's job's. A table name is 1 to 31 characters from `A-Z 0-9 $ _`, in
any case.

OpenVMS has no service that lists a table. To list one, Steward has `SHOW
LOGICAL/FULL` list it in a short-lived process that is you, with the privileges you
switched on (D9), and parses the output. That takes about half a second. One name is
translated in-process with `$TRNLNM`.

Refusals common to all three:
- `404` with `vms_status`: a table that does not exist, or that you may not read
  (OpenVMS says IVLOGTAB or NOLOGTAB for both), or a name not in the table (NOLOGNAM).
- `500` if the listing does not finish within 30 seconds. The helper process is
  deleted.

### `GET api/v1/logicals/tables`

The shareable tables, from `LNM$SYSTEM_DIRECTORY`, as your listing of it shows them.

```json
{"your_group_table": "LNM$GROUP_000362",
 "tables": [
   {"name": "LNM$SYSTEM_TABLE", "mode": "kernel", "kind": "system", "listable": true},
   {"name": "LNM$SYSCLUSTER_TABLE", "mode": "kernel", "kind": "cluster", "listable": true},
   {"name": "LNM$GROUP_000362", "mode": "kernel", "kind": "group", "listable": true}]}
```

- `kind` is `system`, `cluster` (`LNM$SYSCLUSTER_TABLE` or a clusterwide table),
  `group`, `job` or `other`, and is used for grouping in the view.
- `listable` is false for a table the endpoints below refuse: the job tables.
- `your_group_table` is your UIC group's table. `LNM$GROUP` in the endpoints below
  means that table.

### `GET api/v1/logicals?table=&filter=`

The names in a table, as `SHOW LOGICAL/FULL/TABLE=table filter` lists them.
- `table` defaults to `LNM$SYSTEM_TABLE`.
- `filter` defaults to `*`. With `*` or `%` in it, it is a DCL pattern. Without them, it
  matches anywhere in the name (`SYS` is `*SYS*`). Either way it is 1 to 63 characters
  from `A-Z 0-9 $ _ * %`, upper-cased, and anything else is a `400`.

```json
{"table": "LNM$SYSTEM_TABLE", "filter": "SYS$SYSROOT",
 "tables": [
   {"name": "LNM$SYSTEM_TABLE", "mode": "kernel", "attributes": ["shareable", "system"],
    "protection": "(RWC,RWC,R,R)", "owner": "[SYSTEM]",
    "names": [
      {"name": "SYS$SYSROOT", "mode": "exec", "attributes": [],
       "equivalences": [
         {"value": "X86VMS$DKA0:[SYS0.]", "attributes": ["concealed", "terminal"]},
         {"value": "SYS$COMMON:", "attributes": []}]}]}],
 "truncated": false}
```

- `tables` has one entry per table the listing went through. A table name that is a
  search list (`LNM$FILE_DEV` aside, which is refused) lists each of its tables in turn.
- A name keeps its first 16 equivalences. Past that, `more_equivalences` gives how
  many more there are.
- At most 2,000 names are returned. Past that, `truncated` is true.

### `GET api/v1/logicals/{table}/{name}`

One name, every equivalence (`$TRNLNM`), and what each equivalence translates to in
turn, as `SHOW LOGICAL` does.

- `{table}` must be a table in `LNM$SYSTEM_DIRECTORY` with the table attribute, or
  `LNM$GROUP`. A search list of tables, or the directory itself, is a `404`.
- `{name}` is 1 to 255 printable characters (URL-encoded), taken as given: logical names
  are case-sensitive.

```json
{"table": "LNM$SYSTEM_TABLE",
 "logical": {"name": "SYS$SYSROOT", "mode": "exec", "attributes": [],
             "equivalences": [
               {"value": "X86VMS$DKA0:[SYS0.]", "attributes": ["concealed", "terminal"]},
               {"value": "SYS$COMMON:", "attributes": []}]},
 "translations": [
   [],
   [{"name": "SYS$COMMON", "table": "LNM$SYSTEM_TABLE",
     "value": "X86VMS$DKA0:[SYS0.SYSCOMMON.]", "attributes": ["concealed", "terminal"]}]]}
```

- `table` is the table the name was found in.
- `translations` has one list per equivalence: each step's name, the table it was found
  in, and its first equivalence. A value leads on if it is a bare name or a device
  (`SYS$COMMON`, `SYS$COMMON:`, `DATA:[LOG]`). The chain ends at a `terminal`
  equivalence, at a value that is not a name, or after nine steps, as OpenVMS stops.
- Each step is looked up in your group table, then `LNM$SYSTEM_TABLE`, then
  `LNM$SYSCLUSTER_TABLE`, and never in the process or job table. So a step that only a
  process or job name would resolve is not shown.

### `GET api/v1/logical?table=&name=&mode=`

The same as `logicals/{table}/{name}`, with the name as a query parameter, so a name
with `/` in it can be reached. With `mode` (`user`, `super` or `exec`), it gives the
definition at exactly that mode, or `404` NOLOGNAM if the name is not at it; without
it, the outermost. Both answers also carry `modes`: every mode the name
has in that table, outermost first. `SHOW LOGICAL` and `logical` show only the
outermost one.

```json
{"table": "LNM$SYSTEM_TABLE", "logical": {"name": "SYS$SYSROOT", "mode": "exec", ...},
 "modes": ["exec"], "translations": [...]}
```

## Logical names: define and deassign (Phase 7b, D15)

Done **as you**, in-process (`$CRELNM`, `$DELLNM`), with the privileges you switched
on (D9). OpenVMS checks your privileges and the table's protection: on x86, a group
table needs GRPPRV (your own group), GRPNAM or SYSPRV, and the system table needs
SYSPRV or SYSNAM. Both need the CSRF header, and both are audited, without the
equivalences.

Tables are as for reading: a shareable table, never the directory, a process or a job
table. `LNM$GROUP` means your group table.

**Modes** are `user`, `super` (or `supervisor`) and `exec` (or `executive`). Kernel is
refused. Supervisor and executive need **SYSNAM switched on**: without it, Steward
answers `403` with `NOSYSNAM` and does nothing. OpenVMS itself would quietly use user
mode instead, replacing a user-mode name you did not mention.

### `PUT api/v1/logical`

```json
{"table": "LNM$SYSTEM_TABLE", "name": "PROJECT_DATA", "mode": "exec",
 "attributes": ["no_alias"],
 "equivalences": [{"value": "DKA100:[PROJECT.]", "attributes": ["concealed", "terminal"]},
                  {"value": "DKA200:[ARCHIVE]"}],
 "replace": false}
```

- `name` and each `value` are 1 to 255 printable ASCII characters, kept as given. 1 to
  16 equivalences.
- `attributes`: `confine` and `no_alias` on the name; `concealed` and `terminal` on an
  equivalence. Optional.
- **`replace`:** if the name already exists at that mode in that table, the answer is
  `409` unless this is `true`.
- **`no_alias` removes the name at every outer mode**, as OpenVMS does.
- The answer is the name as `GET logical` gives it: `201` if new, `200` if replaced.
  Its `modes` shows what is left.
- A body that is not an object is a `400`. A bad or missing member is a `422`, whose
  `detail` names it.

### `DELETE api/v1/logical?table=&name=&mode=`

Deassigns the name at that mode **and every outer mode**, as `DEASSIGN` does. `mode` is
required. The answer names the modes removed:

```json
{"table": "LNM$SYSTEM_TABLE", "name": "PROJECT_DATA", "removed": ["user", "super"]}
```

`404` with `NOLOGNAM` if the name is at none of those modes.

## Processes (Phase 8, D16)

Read **as you**, by `$GETJPI` in-process: you see your own processes, your UIC
group's with GROUP switched on, and everyone's with WORLD, as at a terminal. The
process serving your request is never listed: under your identity it would show as
one of yours. A PID is 8 hexadecimal digits as `SHOW SYSTEM` lists it, with or
without `%X`.

### `GET api/v1/processes?filter=`

```json
{"processes": [
   {"pid": "00007500", "name": "STEWARD_19300", "username": "STEWARD", "uic": "[362,2]",
    "state": "LEF", "priority": 6, "base_priority": 4, "kind": "detached",
    "terminal": "", "image": "X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]STEWARD.EXE;1",
    "cpu_ms": 1230, "direct_io": 213, "buffered_io": 1720, "page_faults": 979,
    "login": 1792065804}],
 "truncated": false}
```

- `filter`: up to 31 printable characters, matched against the process name and the
  username. With `*` or `%` it is a DCL pattern; without, it matches anywhere.
- `state` is the scheduling state as `SHOW SYSTEM` names it (`LEF`, `HIB`, `COM`,
  `CUR`, ...). `kind` is `interactive`, `batch`, `network`, `detached` or
  `subprocess`.
- At most 4,000 processes; past that, `truncated` is true.

### `GET api/v1/processes/{pid}`

The above, plus what `SHOW PROCESS/ALL` shows:

```json
{"pid": "00007500", ..., "master": "00007500", "subprocesses": 0,
 "working_set_size": 4096, "working_set_pages": 1800,
 "current_privileges": ["IMPERSONATE", "TMPMBX", "NETMBX"],
 "authorized_privileges": ["IMPERSONATE", "TMPMBX", "NETMBX", "SYSPRV"],
 "rights": ["STEWARD_OPS"],
 "quotas": {"astlm": {"limit": 300, "left": 270}, "biolm": {...}, "diolm": {...},
            "fillm": {...}, "prclm": {...}, "tqelm": {...}, "enqlm": {...},
            "bytlm": {...}, "pgflquota": {...}}}
```

- `owner` is there for a subprocess only.
- `403` with NOPRIV for a process you may not see, and `404` with NONEXPR for one that
  does not exist. That is what `SHOW PROCESS/ID=` says, and reveals no more.
- `400` for a PID not in that form.

### `DELETE api/v1/processes/{pid}` (Phase 8b)

Stops the process, as `STOP/ID` does (`$DELPRC`), as you: OpenVMS lets you stop your
own processes, your group's with GROUP and anyone's with WORLD. Needs the CSRF header.

```json
{"pid": "00007D90", "name": "BATCH_232", "username": "STEWARD_TEST", "stopping": true}
```

- `202`: OpenVMS accepted the stop. It is asynchronous: for a moment the process may
  still be listed.
- `409` for a process of Steward's own: its account's, or any running Steward's image
  (a pool worker busy with someone's request is reported under their name), whatever
  your privileges. Use `STEWARD$CONTROL` at a terminal.
- `409` for a system process (UIC group up to SYSGEN's MAXSYSGROUP), whatever your
  privileges. A process's `system` field says which these are.
- `400` for a PID not in OpenVMS's form (`FFFFFFFF` included: OpenVMS's wildcard).
- `403` with NOPRIV and `404` with NONEXPR, as for reading.
- Audited with the PID, process name and username, refusals included.

## Queues (Phase 9, D17): read-only

Read **as you**, by `$GETQUI`: the queue manager judges each request by your
identity. Every queue is listed. A job you may not read is listed by entry number and
status only (`"accessible": false`), as `SHOW QUEUE/ALL` shows it at a terminal.
Whether you may read a job is the queue's protection (the queues here give your UIC
group read access) and your privileges (SYSPRV reads all).

### `GET api/v1/queues`

```json
{"queues": [
   {"name": "X86VMS_BATCH", "kind": "batch", "generic": false, "status": ["busy", "available"],
    "node": "X86VMS", "description": "", "job_limit": 4,
    "executing": 1, "pending": 0, "holding": 0, "timed": 0}]}
```

- `kind` is `batch` or `output` (print, server and terminal queues).
- `status` lists the queue's status as `SHOW QUEUE` words it: `stopped`, `paused`,
  `idle`, `busy`, `available`, `stalled`, ...

### `GET api/v1/queues/{name}`

The queue, as above, and its jobs:

```json
{"name": "SYS$BATCH", ..., "truncated": false,
 "jobs": [
   {"entry": 269, "accessible": true, "name": "NIGHTLY", "username": "STEWARD_TEST",
    "status": ["holding"], "queue": "SYS$BATCH", "submitted": 1792082129},
   {"entry": 270, "accessible": false, "name": "", "username": "", "status": ["holding"],
    "queue": "SYS$BATCH"}]}
```

- `{name}` is 1 to 31 characters from `A-Z 0-9 $ _`; no wildcards. `404` with
  NOSUCHQUE if there is no such queue.
- At most 10,000 jobs; past that, `truncated` is true.

### `GET api/v1/jobs/{entry}`

One job, as `SHOW ENTRY/FULL`: the above, plus `after`, `priority`, `account`, `uic`,
`log` and `files`. `403` with NOPRIV for a job you may not read, `404` with NOSUCHENT
for none, `400` for an entry that is not 1 to 9 digits.

### Changes (Phase 9b)

As you, by `$SNDJBC`; the queue manager decides, as for SET ENTRY, DELETE/ENTRY and
STOP and START/QUEUE at a terminal. Each needs the CSRF header and is audited, refusals
included.

- `POST api/v1/jobs/{entry}/hold`, `POST api/v1/jobs/{entry}/release`, `DELETE
  api/v1/jobs/{entry}`: `200 {"entry": 269, "done": "held"}` (`released`, `deleted`).
  You may change your own jobs; your group may read them but not change them; SYSPRV
  may change any here. Holding a running job is `409` with JBC's EXECUTING. Deleting a
  running job stops it.
- `POST api/v1/queues/{name}/stop`, `POST api/v1/queues/{name}/start`: `200` with the
  queue as `GET api/v1/queues` gives it. Here they need SYSPRV (the queues give system
  `M`), or OPER.
- **`409` for SYS$BATCH and the queues it feeds**, whatever your privileges: Steward's
  pool is started at boot by a job there. If Steward cannot tell which queues those are
  (the queue manager did not say), every stop is `503`. Starting a queue is never
  refused by Steward.
- `403` with JBC NOPRIV where the queue manager refuses; `404` with NOSUCHENT or
  NOSUCHQUE.

## System parameters (Phase 10, D18): read-only

### `GET api/v1/sysgen?filter=`

Every active parameter, as `SYSGEN SHOW/ALL` prints it, read as you: SYSGEN runs in a
short-lived process that is you (as for logical names), with the privileges you
switched on. Any user may run SYSGEN SHOW at a terminal.

```json
{"parameters": [
   {"name": "GBLPAGES", "current": "11390868", "default": "8388608", "min": "8388608",
    "max": "-1", "unit": "Pagelets", "dynamic": true, "ascii": false,
    "internal": {"current": "711930", "default": "524288", "min": "524288", "max": "-1", "unit": "Pages"}},
   {"name": "SCSNODE", "current": "X86VMS", "default": "", "min": "", "max": "ZZZZ",
    "unit": "Ascii", "dynamic": false, "ascii": true}],
 "truncated": false}
```

- Values are strings, as SYSGEN prints them: `-1` as a maximum means no limit; a string
  parameter's values (`ascii`) lose their quotes and padding; some read `(none set)`.
- `internal` is SYSGEN's "internal value" line, in pages, where it gives one.
- `filter`: up to 31 printable characters, matched against the name; `*` and `%` are
  wildcards, plain text matches anywhere.

## Licences (Phase 11, D19): read-only

### `GET api/v1/licenses`

The licences loaded on this node, its charge, and the licence database, read by the
D14 helper process as the viewer, with the privileges switched on in the session:
`SHOW LICENSE/FULL`, `SHOW LICENSE/UNIT_REQUIREMENTS` and `LICENSE LIST/FULL`. Any user
may see the first two. The database is as LMF$LICENSE's protection allows (a system
UIC, SYSPRV, BYPASS, READALL, UIC group 1); a refusal is in `sources`, and `database` is then empty.

```json
{"loaded": [
   {"product": "FMS", "producer": "VSI", "units": "0", "version": "0.0", "release": "(none)",
    "termination": "30-APR-2027", "availability": "", "activity": "0", "per_core": true,
    "options": "X86_64", "other": []}],
 "database": [
   {"product": "BASIC", "producer": "VSI", "issuer": "VSI", "authorization": "ISV-EXAMPLE-D000000000001",
    "units": "0", "version": "0.0", "release": "(none)", "termination": "30-APR-2027",
    "availability": "0", "activity": "000000001", "options": "X86_64", "hardware_id": "",
    "revision": "3", "status": "Active", "command": "ENABLE", "modified_by": "SYSTEM",
    "modified_on": "15-APR-2026 15:22:29.19", "other": []}],
 "truncated": false,
 "node": "X86VMS",
 "charge": {"lines": ["OpenVMS X86_64/LMF Charge Information for node X86VMS", "...",
                      "Type: PCL,   Units Required: 2  (X86_64 Per Core)"],
            "type": "PCL", "units_required": "2"},
 "database_file": {"file": "SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB;1", "created": "20-APR-2023",
                   "created_by": "SYSTEM", "lmf_version": "V2.0"},
 "sources": {"loaded": {"read": true}, "charge": {"read": true},
             "database": {"read": false, "vms_status": "%X0001829C",
                          "vms_message": "%RMS-F-PRV, insufficient privilege or file protection violation"}}}
```

- Values are strings, as LMF prints them (dates as `DD-MMM-YYYY`, "(none)" kept).
- `per_core` (loaded only): SHOW LICENSE's "Per Core License", printed in place of an
  availability. In the database it shows as the option `PCL`.
- `other`: any field Steward does not name, `{"label", "value"}`, so nothing LMF prints
  is lost; an indented line in the database listing continues the field above it.
- `charge.lines`: SHOW LICENSE/UNIT_REQUIREMENTS as printed (its wording varies by
  platform); `type` and `units_required` where its "Type:" line gives them.
- `truncated`: more than 2,000 licences in a part.

## Installed products (Phase 12, D20): read-only

### `GET api/v1/products`

What PCSI has installed and its history (`PRODUCT SHOW PRODUCT/FULL` and `PRODUCT SHOW
HISTORY/FULL`, run in the D14 helper as **you**, with the privileges you switched on),
and VMSINSTAL's own history, read as you. PRODUCT needs your account authorized for
SYSLCK, and switches it on itself, so it need not be switched on in the session; without
it both PCSI parts are refused, in PRODUCT's own words, and VMSINSTAL's history is still
shown.

```json
{"products": [
   {"producer": "VSI", "base": "X86VMS", "name": "SSL3", "version": "V3.0-21",
    "kit_type": "Full LP", "state": "Installed", "maintenance": [],
    "referenced_by": ["VSI X86VMS OPENVMS E9.2-3", "VSI X86VMS TCPIP V6.0-31"]}],
 "history": [
   {"producer": "VSI", "base": "X86VMS", "name": "VMS923X_UPDATE", "version": "V2.0",
    "kit_type": "Patch", "operation": "Install", "validation": "Val",
    "date": "02-MAY-2026 14:40:11", "error": "0", "user": "SYSTEM", "remark": ""}],
 "vmsinstal": [
   {"name": "", "mnemonic": "VSIFMS", "version": "2.6", "date": "5-JUL-2024", "status": "S",
    "ivp": "S", "node": "X86VMS", "installer": "SYSTEM", "signature": "VSI"}],
 "truncated": false,
 "sources": {"products": {"read": true}, "history": {"read": true}, "vmsinstal": {"read": true}}}
```

- `products` in PCSI's order; `history` newest first, as PCSI gives it; `vmsinstal`
  oldest first, as the file holds it. VMSINSTAL records installs only, never a removal.
- Without SYSLCK authorized: `"products": {"read": false, "vms_status": "%X0652800A",
  "vms_message": "%PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege"}`, and the
  same for `history`; both arrays empty.
- Dates are as OpenVMS prints them, in the node's local time.
- `truncated`: more than 5,000 entries in a part.

## Monitoring (Phase 13, D21, D22): read-only

### `GET api/v1/monitor`

One reading of the counters MONITOR shows, from `$GETRMI` and `$GETDVI`, which anyone
may read, and the processes **you** may see (as `GET api/v1/processes`). Raw counters,
as OpenVMS keeps them from boot, and when they were read: rates come from two readings,
and the page works them out and keeps the history (`www/js/rates.js`). Mark a poll
with `X-Steward-Background: 1` so it does not count as activity, as for
`api/v1/system`.

```json
{"sampled_at_ms": 1792202276985, "cpus": 2,
 "modes": {"interrupt": -1858332, "mp_synch": 27036, "kernel": 7908980, "executive": 548076,
           "supervisor": 26870, "user": 815117, "idle": 49936073},
 "states": {"CUR": 2, "COM": 0, "COMO": 0, "LEF": 50, "LEFO": 0, "HIB": 54, "HIBO": 0,
            "SUSP": 0, "SUSPO": 0, "PFW": 0, "MWAIT": 0, "CEF": 0, "COLPG": 0, "FPG": 0},
 "processes": 105,
 "memory": {"total": 7620722688, "free": 5068750848, "modified": 20324352},
 "counters": {"page_faults": 53270380, "page_read_io": 4728534, "page_write_io": 0, "inswaps": 0,
              "direct_io": 14061387, "buffered_io": 96706846, "mailbox_reads": 13695616,
              "mailbox_writes": 13625570},
 "disks": [{"device": "DKA0:", "operations": 2146577}],
 "visible": [{"pid": "00007520", "name": "STEWARD_TEST", "username": "STEWARD_TEST", "state": "LEF",
              "cpu_ms": 350, "direct_io": 120, "buffered_io": 300, "page_faults": 800}],
 "truncated": false}
```

- `modes`: ticks summed over the CPUs, 100 a second a CPU. `interrupt` can be negative
  (it is on the x86 VM); the page shows it as 0, as MONITOR does.
- `states`: processes in each state now, by MONITOR's and SHOW SYSTEM's names; their
  total need not equal `processes` exactly.
- `counters` and `operations` wrap at 2^32.
- `disks`: those the dashboard lists, the system disk first.
- `visible`: the processes `$GETJPI` shows you (your own; your group's with GROUP;
  everyone's with WORLD), never the one serving the request; `truncated` past 4,000.

### `GET api/v1/monitor/history?minutes=&points=`

Readings from the recording on the node (D22): the recorder (`steward -r`, started with
the pool) writes one each interval, 60 s by default, kept for 7 days. Up to `points`
(2 to 1000, default 300) readings spread over the last `minutes` (1 to 527,040, default
360; cut to what the recording keeps), a whole number of intervals apart (`step_secs`),
oldest first. Each is `GET api/v1/monitor`'s reading without `visible` and `truncated`:
processes are not recorded. The counters being cumulative, two readings give the exact
average between them, so the page's `rates.js` works on them unchanged. A reading that
was never written (the recorder stopped, a reboot) is simply missing. Anyone signed in
may read it, as anyone may read the counters. Background polls as above.

```json
{"recording": true, "interval_secs": 60, "kept_secs": 604800,
 "started_ms": 1792190000000, "updated_ms": 1792202280012, "step_secs": 120,
 "readings": [{"sampled_at_ms": 1792180680031, "cpus": 2, "modes": {...}, "states": {...},
               "processes": 104, "memory": {...}, "counters": {...}, "disks": [...]}]}
```

Without a recording (the recorder off, or not started yet): `{"recording": false,
"readings": []}`.

## Coming

The error log and a terminal (`docs/PLAN.md`).
