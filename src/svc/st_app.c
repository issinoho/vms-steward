/* st_app.c - request dispatch: routing, sessions, CSRF, personas.

   Everything a handler may assume is established here, in this order:
     1. the route exists and allows the method              (404 / 405)
     2. a body, if any, is JSON and within limits           (413 / 415)
     3. state-changing requests come from our own origin    (403)
     4. for routes that need one, a live session            (401)
     5. for state-changing requests, the session's CSRF token (403)
     6. the caller's persona is assumed                     (D2)
   and the persona is ended on every path out, which is why handlers never call
   st_plat_persona_begin or _end themselves. */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

enum { R_PUBLIC = 1, R_NOPERSONA = 2 };

typedef struct {
    const char *method;
    const char *pattern;
    void      (*handler)(st_ctx *);
    unsigned    flags;
} route;

static const route routes[] = {
    { "GET",    "/api/v1/health",  svc_health,         R_PUBLIC | R_NOPERSONA },
    { "POST",   "/api/v1/session", svc_session_login,  R_PUBLIC | R_NOPERSONA },
    { "GET",    "/api/v1/session", svc_session_get,    0 },
    { "DELETE", "/api/v1/session", svc_session_logout, R_NOPERSONA },
    { "PUT",    "/api/v1/session/privileges", svc_session_privileges, 0 },
    { "GET",    "/api/v1/system",                      svc_system,           0 },
    { "GET",    "/api/v1/access",                      svc_access,           0 },
    { "GET",    "/api/v1/logicals/tables",             svc_logical_tables,   0 },
    { "GET",    "/api/v1/logicals",                    svc_logicals,         0 },
    { "GET",    "/api/v1/logicals/{t}/{n}",            svc_logical_get,      0 },
    { "GET",    "/api/v1/logical",                     svc_logical_one,      0 },
    { "PUT",    "/api/v1/logical",                     svc_logical_define,   0 },
    { "DELETE", "/api/v1/logical",                     svc_logical_deassign, 0 },
    { "GET",    "/api/v1/processes",                   svc_processes,        0 },
    { "GET",    "/api/v1/processes/{p}",               svc_process_get,      0 },
    { "DELETE", "/api/v1/processes/{p}",               svc_process_stop,     0 },
    { "GET",    "/api/v1/queues",                      svc_queues,           0 },
    { "GET",    "/api/v1/queues/{q}",                  svc_queue_get,        0 },
    { "GET",    "/api/v1/jobs/{j}",                    svc_job_get,          0 },
    { "POST",   "/api/v1/jobs/{j}/hold",               svc_job_hold,         0 },
    { "POST",   "/api/v1/jobs/{j}/release",            svc_job_release,      0 },
    { "DELETE", "/api/v1/jobs/{j}",                    svc_job_delete,       0 },
    { "POST",   "/api/v1/queues/{q}/stop",             svc_queue_stop,       0 },
    { "POST",   "/api/v1/queues/{q}/start",            svc_queue_start,      0 },
    { "GET",    "/api/v1/sysgen",                      svc_sysgen,           0 },
    { "GET",    "/api/v1/licenses",                    svc_licenses,         0 },
    { "GET",    "/api/v1/products",                    svc_products,         0 },
    { "GET",    "/api/v1/products/kits",               svc_product_kits,     0 },
    { "POST",   "/api/v1/products/install",            svc_product_install,  0 },
    { "POST",   "/api/v1/products/remove",             svc_product_remove,   0 },
    { "GET",    "/api/v1/products/log",                svc_product_log,      0 },
    { "GET",    "/api/v1/monitor",                     svc_monitor,          0 },
    { "GET",    "/api/v1/monitor/history",             svc_monitor_history,  0 },
    { "GET",    "/api/v1/errorlog",                    svc_errorlog,         0 },
    { "GET",    "/api/v1/errorlog/files",              svc_errorlog_files,   0 },
    { "POST",   "/api/v1/errorlog/new",                svc_errorlog_new,     0 },
    { "GET",    "/api/v1/errorlog/{n}",                svc_errorlog_event,   0 },
    { "GET",    "/api/v1/crashes",                     svc_crashes,          0 },
    { "POST",   "/api/v1/crashes/purge",               svc_crash_purge,      0 },
    { "GET",    "/api/v1/crashes/{c}",                 svc_crash_get,        0 },
    { "DELETE", "/api/v1/crashes/{c}",                 svc_crash_delete,     0 },
    { "GET",    "/api/v1/operator-log",                svc_operator_log,     0 },
    { "GET",    "/api/v1/device-errors",               svc_device_errors,    0 },
    { "GET",    "/api/v1/users",                       svc_users_list,       0 },
    { "GET",    "/api/v1/users/{u}",                   svc_user_get,         0 },
    { "GET",    "/api/v1/users/{u}/identifiers",       svc_user_identifiers, 0 },
    { "GET",    "/api/v1/identifiers",                 svc_idents_list,      0 },
    { "GET",    "/api/v1/identifiers/{id}",            svc_ident_get,        0 },
    { "GET",    "/api/v1/identifiers/{id}/holders",    svc_ident_holders,    0 },
    /* Phase 3: changes */
    { "PATCH",  "/api/v1/users/{u}",                   svc_user_modify,      0 },
    { "POST",   "/api/v1/users",                       svc_user_create,      0 },
    { "DELETE", "/api/v1/users/{u}",                   svc_user_delete,      0 },
    { "GET",    "/api/v1/uic/next",                    svc_uic_next,         0 },
    { "POST",   "/api/v1/users/{u}/password",          svc_user_set_password, 0 },
    { "POST",   "/api/v1/users/{u}/identifiers",       svc_user_grant,       0 },
    { "PUT",    "/api/v1/users/{u}/identifiers/{id}",  svc_user_holding,     0 },
    { "DELETE", "/api/v1/users/{u}/identifiers/{id}",  svc_user_revoke,      0 },
    { "POST",   "/api/v1/identifiers",                 svc_ident_create,     0 },
    { "PATCH",  "/api/v1/identifiers/{id}",            svc_ident_modify,     0 },
    { "DELETE", "/api/v1/identifiers/{id}",            svc_ident_delete,     0 },
    /* Anyone, signed in or not (an expired password cannot sign in): the current
       password is the authentication. */
    { "POST",   "/api/v1/session/password",            svc_password_change,  R_PUBLIC | R_NOPERSONA },
};
#define NROUTES (sizeof routes / sizeof routes[0])

static st_app_config config;

void st_app_init(const st_app_config *cfg) { config = *cfg; }

static int is_safe(const char *m) { return !strcmp(m, "GET") || !strcmp(m, "HEAD"); }

static void problem(st_ctx *c, int status, const char *slug, const char *title,
                    const char *detail)
{
    st_resp_problem(c->resp, status, slug, title, detail, 0, NULL);
}

void st_app_error(st_ctx *c, const st_err *e)
{
    static const struct { int kind, status; const char *slug, *title; } map[] = {
        { ST_E_NOPRIV,   403, "no-privilege",  "Not permitted by OpenVMS" },
        { ST_E_NOTFOUND, 404, "not-found",     "Not found" },
        { ST_E_INVALID,  422, "invalid-value", "OpenVMS rejected a value" },
        { ST_E_CONFLICT, 409, "conflict",      "Conflict" },
    };
    size_t i;
    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (map[i].kind == e->kind) {
            st_resp_problem(c->resp, map[i].status, map[i].slug, map[i].title, NULL,
                            e->cond, e->text);
            return;
        }
    st_resp_problem(c->resp, 500, "internal", "Internal error", NULL, e->cond, e->text);
}

int st_app_body(st_ctx *c, st_jdoc *doc)
{
    char err[96];
    if (st_json_parse(doc, c->req->body ? c->req->body : "", c->req->body_len, err, sizeof err)) {
        problem(c, 400, "bad-json", "Request body is not valid JSON", err);
        return -1;
    }
    return 0;
}

/* Audit records are key=value pairs on one line; values are quoted, with quotes,
   backslashes, control characters and anything outside ASCII escaped. So a crafted
   username or detail cannot forge a second record, and the file is plain ASCII
   whichever character set a value arrived in. */
static void kv(char *out, size_t outlen, const char *key, const char *val)
{
    size_t o = strlen(out);
    if (o + strlen(key) + 4 >= outlen) return;
    o += (size_t) snprintf(out + o, outlen - o, "%s%s=\"", o ? " " : "", key);
    for (; val && *val && o + 6 < outlen; val++) {
        unsigned char ch = (unsigned char) *val;
        if (ch == '"' || ch == '\\') { out[o++] = '\\'; out[o++] = (char) ch; }
        else if (ch < 0x20 || ch >= 0x7F) o += (size_t) snprintf(out + o, outlen - o, "\\x%02x", ch);
        else out[o++] = (char) ch;
    }
    out[o++] = '"';
    out[o] = '\0';
}

void st_app_audit(st_ctx *c, const char *user, const char *action, const char *target,
                  const char *outcome, const char *detail)
{
    char line[1024];
    line[0] = '\0';
    kv(line, sizeof line, "user", user);
    kv(line, sizeof line, "client", c->client);
    kv(line, sizeof line, "action", action);
    kv(line, sizeof line, "target", target);
    kv(line, sizeof line, "outcome", outcome);
    if (detail && *detail) kv(line, sizeof line, "detail", detail);
    st_plat_audit(line);
}

void st_app_set_cookie(st_ctx *c, const char *token_hex, long max_age)
{
    char v[400];
    /* The path follows the proxy's mount point, so the cookie still reaches /api
       when the site is published under a prefix (D7). */
    snprintf(v, sizeof v, "%s=%s; Path=%s/api; Max-Age=%ld; HttpOnly; SameSite=Strict%s", ST_COOKIE,
            token_hex, c->prefix, max_age, c->cfg->cookie_secure ? "; Secure" : "");
    st_resp_header(c->resp, "Set-Cookie", v);
}

/* A state-changing request must come from a page we served. Browsers send Origin on
   cross-origin requests and on same-origin POST/PUT/PATCH/DELETE. Sec-Fetch-Site,
   when present, settles it directly. Neither header present means a non-browser
   client, which a session cookie alone cannot be ridden by. */
static int same_origin(const st_ctx *c)
{
    const char *site = st_req_header(c->req, "HTTP_SEC_FETCH_SITE");
    const char *origin = st_req_header(c->req, "HTTP_ORIGIN");
    char want[300];
    if (site && strcmp(site, "same-origin") && strcmp(site, "none")) return 0;
    if (!origin) return 1;
    if (!*c->host) return 0;
    snprintf(want, sizeof want, "%s://%s", c->scheme, c->host);   /* as the browser saw it (D7) */
    return !strcmp(origin, want);
}

/* ---- reverse proxies (D7) ----

   Behind nginx (proxy manager) or any other proxy, lighttpd's REMOTE_ADDR is the
   proxy, the scheme is whatever the proxy used to reach us, and the browser's
   address, scheme, host and mount point arrive in X-Forwarded-* headers. Those headers
   are believed only when the connection comes from a configured trusted proxy;
   otherwise anyone could choose the address their failed logins are charged to. */

static int parse_ipv4(const char *s, size_t n, unsigned long *out)
{
    unsigned long v = 0, part;
    int dots = 0;
    size_t i = 0;
    while (i < n) {
        size_t digits = 0;
        part = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9' && digits < 4) {
            part = part * 10 + (unsigned long) (s[i++] - '0');
            digits++;
        }
        if (!digits || part > 255) return 0;
        v = (v << 8) | part;
        if (i == n) break;
        if (s[i++] != '.' || ++dots > 3) return 0;
    }
    if (dots != 3) return 0;
    *out = v & 0xFFFFFFFFul;
    return 1;
}

static int ieq(const char *a, size_t an, const char *b, size_t bn)
{
    size_t i;
    if (an != bn) return 0;
    for (i = 0; i < an; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char) (x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char) (y - 'A' + 'a');
        if (x != y) return 0;
    }
    return 1;
}

/* Is addr[0..n) one of the trusted proxies? Entries are exact addresses (IPv4 or
   IPv6) or IPv4 CIDR ranges. */
static int trusted(const char *list, const char *addr, size_t n)
{
    unsigned long a = 0;
    int is4 = parse_ipv4(addr, n, &a);
    while (list && *list) {
        const char *end = strchr(list, ','), *slash;
        size_t len;
        while (*list == ' ') list++;
        if (!end) end = list + strlen(list);
        len = (size_t) (end - list);
        while (len && list[len - 1] == ' ') len--;
        slash = memchr(list, '/', len);
        if (slash && is4) {
            unsigned long net, mask;
            int bits = 0;
            const char *b = slash + 1;
            while (b < list + len && *b >= '0' && *b <= '9' && bits <= 32) bits = bits * 10 + (*b++ - '0');
            if (b == list + len && bits <= 32 && parse_ipv4(list, (size_t) (slash - list), &net)) {
                mask = bits ? (0xFFFFFFFFul << (32 - bits)) & 0xFFFFFFFFul : 0;
                if ((a & mask) == (net & mask)) return 1;
            }
        } else if (!slash && ieq(list, len, addr, n)) {
            return 1;
        }
        list = *end ? end + 1 : end;
    }
    return 0;
}

static void copy_n(char *out, size_t outlen, const char *s, size_t n)
{
    if (n >= outlen) n = outlen - 1;
    memcpy(out, s, n);
    out[n] = '\0';
}

/* The first comma-separated token of a header, trimmed. */
static size_t first_token(const char *h, const char **start)
{
    size_t n;
    while (*h == ' ') h++;
    *start = h;
    n = strcspn(h, ",");
    while (n && h[n - 1] == ' ') n--;
    return n;
}

static int host_ok(const char *s, size_t n)
{
    size_t i;
    if (n == 0 || n > 255) return 0;
    for (i = 0; i < n; i++) {
        char ch = s[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']'))
            return 0;
    }
    return 1;
}

static int prefix_ok(const char *s, size_t n)
{
    size_t i;
    if (n == 0 || n > 120 || s[0] != '/') return 0;
    for (i = 0; i < n; i++) {
        char ch = s[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '/' || ch == '-' || ch == '_' || ch == '.'))
            return 0;
        if (ch == '.' && i > 0 && s[i - 1] == '.') return 0;
    }
    return 1;
}

void st_app_origin(st_ctx *c, const char *proxies)
{
    const st_request *r = c->req;
    const char *ra = r->remote_addr, *h, *t;
    const char *https = st_req_param(r, "HTTPS");
    size_t n;

    copy_n(c->client, sizeof c->client, ra, strlen(ra));
    st_copy(c->scheme, sizeof c->scheme, (https && !strcmp(https, "on")) ? "https" : "http");
    h = st_req_header(r, "HTTP_HOST");
    c->host[0] = '\0';
    if (h && host_ok(h, strlen(h))) copy_n(c->host, sizeof c->host, h, strlen(h));
    c->prefix[0] = '\0';

    if (!proxies || !*proxies || !trusted(proxies, ra, strlen(ra))) return;

    /* Client: walk X-Forwarded-For from the right, past our own proxies; the first
       address that is not one of them is the one that connected to the outermost
       proxy we trust. Anything further left was written by the client itself. */
    h = st_req_header(r, "HTTP_X_FORWARDED_FOR");
    if (h) {
        const char *end = h + strlen(h);
        while (end > h) {
            const char *tok = end, *s, *e2;
            while (tok > h && tok[-1] != ',') tok--;
            s = tok;
            e2 = end;
            while (s < e2 && *s == ' ') s++;
            while (e2 > s && e2[-1] == ' ') e2--;
            n = (size_t) (e2 - s);
            {
                char tmp[46];
                if (n == 0 || n >= sizeof tmp) break;
                copy_n(tmp, sizeof tmp, s, n);
                if (!st_valid_ip(tmp)) break;   /* garbage: keep the last good hop */
                st_copy(c->client, sizeof c->client, tmp);
                if (!trusted(proxies, s, n)) break;
            }
            end = tok > h ? tok - 1 : h;   /* the comma before this hop */
        }
    }
    h = st_req_header(r, "HTTP_X_FORWARDED_PROTO");
    if (h) {
        n = first_token(h, &t);
        if (ieq(t, n, "https", 5)) st_copy(c->scheme, sizeof c->scheme, "https");
        else if (ieq(t, n, "http", 4)) st_copy(c->scheme, sizeof c->scheme, "http");
    }
    h = st_req_header(r, "HTTP_X_FORWARDED_HOST");
    if (h) {
        n = first_token(h, &t);
        if (host_ok(t, n)) copy_n(c->host, sizeof c->host, t, n);
    }
    h = st_req_header(r, "HTTP_X_FORWARDED_PREFIX");
    if (h) {
        n = first_token(h, &t);
        while (n > 1 && t[n - 1] == '/') n--;
        if (prefix_ok(t, n) && !(n == 1 && t[0] == '/')) copy_n(c->prefix, sizeof c->prefix, t, n);
    }
}

/* 1 with c->session filled, 0 with the 401 response set, -1 with an error set. */
static int load_session(st_ctx *c)
{
    char hex[80];
    unsigned char token[32], key[32];
    st_err e;
    long long now = st_plat_time();
    int got;

    if (!st_req_cookie(c->req, ST_COOKIE, hex, sizeof hex) || !st_unhex(hex, token, 32)) {
        problem(c, 401, "not-signed-in", "Not signed in", NULL);
        return 0;
    }
    st_plat_sha256(token, 32, key);
    st_zero(token, sizeof token);
    st_zero(hex, sizeof hex);
    got = st_plat_session_get(key, &c->session, &e);
    if (got < 0) { st_app_error(c, &e); return -1; }
    if (got == 0) {
        problem(c, 401, "not-signed-in", "Not signed in", "The session has ended.");
        return 0;
    }
    if (now - c->session.last_seen > c->cfg->idle_secs ||
        now - c->session.created > c->cfg->absolute_secs) {
        st_plat_session_delete(key, &e);
        st_app_audit(c, c->session.username, "session-expired", "-", "ok", NULL);
        problem(c, 401, "session-expired", "Session expired", NULL);
        return 0;
    }
    /* A background poll (the dashboard's refresh) is not activity: with it counted, a
       page left open would keep its session alive for ever and the idle timeout would
       never fire. The browser marks such requests; marking one changes nothing else. */
    {
        const char *bg = st_req_header(c->req, "HTTP_X_STEWARD_BACKGROUND");
        if (bg && !strcmp(bg, "1")) { c->has_session = 1; return 1; }
    }
    if (now - c->session.last_seen >= 60) {   /* at most one store write a minute */
        c->session.last_seen = now;
        st_plat_session_put(&c->session, &e);
    }
    c->has_session = 1;
    return 1;
}

static int check_csrf(st_ctx *c)
{
    const char *h = st_req_header(c->req, "HTTP_X_STEWARD_CSRF");
    unsigned char got[32];
    if (!h || !st_unhex(h, got, 32) || !st_ct_equal(got, c->session.csrf, 32)) {
        problem(c, 403, "csrf", "Missing or wrong X-Steward-CSRF header", NULL);
        return 0;
    }
    return 1;
}

/* The request came through our lighttpd: it carries the gateway secret. */
static int via_gateway(const st_request *r)
{
    const char *want = config.gateway_secret, *got;
    size_t n;
    if (!want || !*want) return 1;
    got = st_req_header(r, "HTTP_X_STEWARD_GATEWAY");
    n = strlen(want);
    return got && strlen(got) == n && st_ct_equal(got, want, n);
}

static int is_json(const st_request *r)
{
    const char *ct = st_req_param(r, "CONTENT_TYPE");
    size_t n = strlen("application/json");
    return ct && !strncmp(ct, "application/json", n) && (ct[n] == '\0' || ct[n] == ';');
}

void st_app_handle(const st_request *req, int body_overflow, st_response *resp)
{
    st_ctx c;
    const route *rt = NULL;
    int path_matched = 0;
    size_t i;
    char allow[64] = "";

    memset(&c, 0, sizeof c);
    c.req = req;
    c.resp = resp;
    c.cfg = &config;
    st_app_origin(&c, config.trusted_proxies);

    if (!via_gateway(req)) {
        /* Not from our lighttpd. No detail for the caller; one log line for us. */
        st_plat_log("refused a request without the gateway secret");
        problem(&c, 403, "forbidden", "Forbidden", NULL);
        return;
    }

    for (i = 0; i < NROUTES; i++) {
        int m = st_route_match(routes[i].pattern, req->path, c.args, ST_ROUTE_ARGS, &c.nargs);
        if (m < 0) { problem(&c, 400, "bad-path", "Badly encoded path", NULL); return; }
        if (!m) continue;
        path_matched = 1;
        if (*allow) st_append(allow, sizeof allow, ", ");
        st_append(allow, sizeof allow, routes[i].method);
        if (!strcmp(routes[i].method, req->method)) { rt = &routes[i]; break; }
    }
    if (!rt) {
        if (path_matched) {
            problem(&c, 405, "method-not-allowed", "Method not allowed", NULL);
            st_resp_header(resp, "Allow", allow);
        } else {
            problem(&c, 404, "no-such-endpoint", "No such endpoint", NULL);
        }
        return;
    }

    if (body_overflow) { problem(&c, 413, "too-large", "Request body too large", NULL); return; }
    if (req->body_len > 0 && !is_json(req)) {
        problem(&c, 415, "json-only", "Request bodies must be application/json", NULL);
        return;
    }
    if (!is_safe(req->method) && !same_origin(&c)) {
        problem(&c, 403, "cross-origin", "Cross-origin request refused", NULL);
        return;
    }
    if (!(rt->flags & R_PUBLIC)) {
        if (load_session(&c) != 1) return;
        if (!is_safe(req->method) && !check_csrf(&c)) return;
    }

    if (!(rt->flags & R_NOPERSONA)) {
        st_err e;
        if (st_plat_persona_begin(c.session.username, c.session.priv_enable, &e)) {
            st_plat_log("persona_begin failed");
            st_app_error(&c, &e);
            return;
        }
        rt->handler(&c);
        st_plat_persona_end();
    } else {
        rt->handler(&c);
    }
}
