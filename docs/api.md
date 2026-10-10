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
   "status": 403, "vms_status": "%X00002964",
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

### `DELETE api/v1/session`: sign out

`204`; the session is deleted and the cookie cleared.

## Coming

Users and rights identifiers (Phases 2-4) are listed in `docs/PLAN.md`. Access history
is Phase 6.
