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

## Coming

Creating, copying and deleting users is Phase 4 (`docs/PLAN.md`). Access history is
Phase 6.
