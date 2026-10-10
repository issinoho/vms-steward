/* svc_session.c - sign in, who am I, sign out. */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

/* PRVDEF bit order. DETACH is shown as IMPERSONATE, its name since V6.0. */
static const char *const priv_names[] = {
    "CMKRNL", "CMEXEC", "SYSNAM", "GRPNAM", "ALLSPOOL", "IMPERSONATE", "DIAGNOSE",
    "LOG_IO", "GROUP", "NOACNT", "PRMCEB", "PRMMBX", "PSWAPM", "ALTPRI", "SETPRV",
    "TMPMBX", "WORLD", "MOUNT", "OPER", "EXQUOTA", "NETMBX", "VOLPRO", "PHY_IO",
    "BUGCHK", "PRMGBL", "SYSGBL", "PFNMAP", "SHMEM", "SYSPRV", "BYPASS", "SYSLCK",
    "SHARE", "UPGRADE", "DOWNGRADE", "GRPPRV", "READALL", "IMPORT", "AUDIT", "SECURITY"
};

const char *svc_priv_name(int bit)
{
    if (bit < 0 || bit >= (int) (sizeof priv_names / sizeof priv_names[0])) return NULL;
    return priv_names[bit];
}

static void privs(st_jw *w, const char *key, const unsigned int q[2])
{
    int bit;
    st_jw_key(w, key);
    st_jw_arr(w);
    for (bit = 0; bit < 64; bit++)
        if (q[bit / 32] & (1u << (bit % 32))) {
            const char *n = svc_priv_name(bit);
            if (n) st_jw_str(w, n);
        }
    st_jw_arr_end(w);
}

void svc_health(st_ctx *c)
{
    st_jw w;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "status", "ok");
    st_jw_obj_end(&w);
}

void svc_session_login(st_ctx *c)
{
    st_jdoc doc;
    const char *u8user, *u8pw;
    char user[ST_USERNAME_MAX + 1], pw[256], token_hex[65], csrf_hex[65];
    unsigned char token[32];
    st_session s;
    st_err e;
    int rc;

    if (c->has_session) {   /* not reachable today: the route is public */
        st_resp_problem(c->resp, 409, "signed-in", "Already signed in", NULL, 0, NULL);
        return;
    }
    if (st_app_body(c, &doc)) return;
    u8user = st_json_get_str(doc.root, "username");
    u8pw = st_json_get_str(doc.root, "password");
    if (!u8user || !u8pw || !*u8pw) {
        st_json_free(&doc);
        st_resp_problem(c->resp, 400, "bad-request", "username and password are required",
                        NULL, 0, NULL);
        return;
    }
    if (!st_valid_username(u8user, user) ||
        st_json_latin1(u8pw, strlen(u8pw), pw, sizeof pw)) {
        /* Malformed input fails the same way as a wrong password, without calling
           $ACM, so it cannot be used to tell the two apart. The audit line is written
           before the document is freed: freeing scrubs the strings u8user points into. */
        st_app_audit(c, strlen(u8user) < 40 ? u8user : "-", "login", "-",
                     "failed", "malformed username or password");
        st_json_free(&doc);
        st_resp_problem(c->resp, 401, "sign-in-failed", "Sign-in failed", NULL, 0, NULL);
        return;
    }
    st_json_free(&doc);   /* scrubs the decoded password */

    rc = st_plat_authenticate(user, pw, st_valid_ip(c->client) ? c->client : "unknown", &e);
    st_zero(pw, sizeof pw);

    if (rc == ST_AUTH_FAILED) {
        st_app_audit(c, user, "login", "-", "failed", e.text);
        st_resp_problem(c->resp, 401, "sign-in-failed", "Sign-in failed", NULL, 0, NULL);
        return;
    }
    if (rc == ST_AUTH_EXPIRED) {
        /* Only reachable with the right password, so it gives nothing away. */
        st_app_audit(c, user, "login", "-", "expired", e.text);
        st_resp_problem(c->resp, 403, "password-expired", "Password expired",
                        "Your password has expired and must be changed before you can sign in.",
                        0, NULL);
        return;
    }
    if (rc != ST_AUTH_OK) {
        st_app_audit(c, user, "login", "-", "error", e.text);
        st_resp_problem(c->resp, 503, "auth-unavailable", "Sign-in is unavailable",
                        NULL, e.cond, e.text);
        return;
    }

    {
        long long now = st_plat_time();
        st_plat_session_purge(now - c->cfg->absolute_secs, now - c->cfg->idle_secs);
    }
    memset(&s, 0, sizeof s);
    if (!st_plat_random(token, sizeof token) || !st_plat_random(s.csrf, sizeof s.csrf)) {
        st_resp_problem(c->resp, 500, "internal", "No random numbers", NULL, 0, NULL);
        return;
    }
    st_plat_sha256(token, sizeof token, s.key);
    st_copy(s.username, sizeof s.username, user);
    s.created = s.last_seen = st_plat_time();
    st_copy(s.client, sizeof s.client, c->client);
    if (st_plat_session_put(&s, &e)) {
        st_zero(token, sizeof token);
        st_app_error(c, &e);
        return;
    }
    st_hex(token, sizeof token, token_hex);
    st_zero(token, sizeof token);
    st_hex(s.csrf, sizeof s.csrf, csrf_hex);

    st_app_audit(c, user, "login", "-", "ok", NULL);
    st_app_set_cookie(c, token_hex, c->cfg->absolute_secs);
    st_zero(token_hex, sizeof token_hex);
    {
        st_jw w;
        st_resp_json(c->resp, 201, &w);
        st_jw_obj(&w);
        st_jw_kstr(&w, "username", user);
        st_jw_kstr(&w, "csrf", csrf_hex);
        st_jw_kint(&w, "idle_timeout", c->cfg->idle_secs);
        st_jw_kint(&w, "expires_at", s.created + c->cfg->absolute_secs);
        st_jw_obj_end(&w);
    }
}

void svc_session_get(st_ctx *c)
{
    st_whoami who;
    st_err e;
    st_jw w;
    char uic[32], csrf_hex[65];
    int i;

    if (st_plat_whoami(&who, &e)) { st_app_error(c, &e); return; }
    snprintf(uic, sizeof uic, "[%o,%o]", who.uic >> 16, who.uic & 0xFFFF);
    st_hex(c->session.csrf, sizeof c->session.csrf, csrf_hex);

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "username", who.username);
    st_jw_kstr(&w, "owner", who.owner);
    st_jw_kstr(&w, "account", who.account);
    st_jw_kstr(&w, "uic", uic);
    privs(&w, "authorized_privileges", who.priv_auth);
    privs(&w, "current_privileges", who.priv_cur);
    st_jw_key(&w, "identifiers");
    st_jw_arr(&w);
    for (i = 0; i < who.nids; i++) st_jw_str(&w, who.ids[i]);
    st_jw_arr_end(&w);
    st_jw_kstr(&w, "csrf", csrf_hex);
    st_jw_kint(&w, "idle_timeout", c->cfg->idle_secs);
    st_jw_kint(&w, "expires_at", c->session.created + c->cfg->absolute_secs);
    st_jw_obj_end(&w);
}

void svc_session_logout(st_ctx *c)
{
    st_err e;
    if (st_plat_session_delete(c->session.key, &e)) { st_app_error(c, &e); return; }
    st_app_audit(c, c->session.username, "logout", "-", "ok", NULL);
    st_app_set_cookie(c, "", 0);
    c->resp->status = 204;
}
