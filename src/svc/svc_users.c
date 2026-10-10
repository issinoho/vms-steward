/* svc_users.c - users (SYSUAF), read-only: list, detail, identifiers held.

   Everything runs under the caller's persona (D2), so what comes back is what
   OpenVMS lets that user read: a refusal is the OS's, passed on as 403 with its
   message. Nothing here decides who may see what. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

/* Indexed by ST_UF_*; the names AUTHORIZE uses. */
static const char *const flag_names[ST_UF_COUNT] = {
    "DISCTLY", "DEFCLI", "LOCKPWD", "RESTRICTED", "DISUSER", "DISWELCOME",
    "DISNEWMAIL", "DISMAIL", "GENPWD", "PWD_EXPIRED", "PWD2_EXPIRED", "AUDIT",
    "DISREPORT", "DISRECONNECT", "AUTOLOGIN", "DISFORCE_PWD_CHANGE", "CAPTIVE",
    "DISIMAGE", "DISPWDDIC", "DISPWDHIS", "DEFCLSVAL", "EXTAUTH", "MIGRATEPWD",
    "VMSAUTH", "DISPWDSYNCH", "PWDMIX"
};

/* Case-insensitive lookup in a name table; -1 if absent. */
int svc_name_index(const char *const *table, int n, const char *name)
{
    int i;
    size_t k;
    for (i = 0; i < n; i++) {
        const char *t = table[i];
        for (k = 0; t[k] && name[k]; k++) {
            char c = name[k];
            if (c >= 'a' && c <= 'z') c = (char) (c - 'a' + 'A');
            if (c != t[k] && !(t[k] >= 'a' && t[k] <= 'z' && c == t[k] - 'a' + 'A')) break;
        }
        if (!t[k] && !name[k]) return i;
    }
    return -1;
}

int svc_flag_bit(const char *name) { return svc_name_index(flag_names, ST_UF_COUNT, name); }

const char *const svc_access_names[ST_ACC_COUNT] = {
    "network", "batch", "local", "dialup", "remote"
};

const char *const svc_quota_names[ST_Q_COUNT] = {
    "prio", "queprio", "maxjobs", "maxacctjobs", "maxdetach", "prclm", "biolm", "diolm",
    "astlm", "tqelm", "enqlm", "fillm", "shrfillm", "bytlm", "pbytlm", "jtquota",
    "wsdef", "wsquo", "wsextent", "pgflquo", "cpu"
};

const char *const svc_day_names[7] = { "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN" };

#define LIMIT_DEFAULT 50
#define LIMIT_MAX     200

void svc_uic_text(unsigned int uic, char out[24])
{
    snprintf(out, 24, "[%o,%o]", uic >> 16, uic & 0xFFFF);
}

static int check_username(const char *in, char out[32])
{
    return st_valid_username(in, out);
}

/* Is name= present in the query string at all? st_req_query cannot say: it returns
   0 both for "absent" and for "too long or badly encoded", and a parameter that is
   present but unusable must be refused, not ignored (security.md checklist). */
static int has_param(const st_request *r, const char *name)
{
    const char *q = r->query;
    size_t n = strlen(name);
    while (q && *q) {
        if (!strncmp(q, name, n) && q[n] == '=') return 1;
        q = strchr(q, '&');
        if (q) q++;
    }
    return 0;
}

/* The named parameter: 1 with raw filled, 0 if absent, -1 (400 set) if present but
   too long or badly encoded. */
int svc_query(st_ctx *c, const char *name, char *raw, size_t rawlen)
{
    if (st_req_query(c->req, name, raw, rawlen)) return 1;
    if (!has_param(c->req, name)) return 0;
    st_resp_problem(c->resp, 400, "bad-request", "Bad query parameter", name, 0, NULL);
    return -1;
}

int svc_list_query(st_ctx *c, char filter[32], char after[32], int *limit,
                   int (*check)(const char *in, char out[32]))
{
    char raw[64];
    int got;
    filter[0] = after[0] = '\0';
    *limit = LIMIT_DEFAULT;
    if ((got = svc_query(c, "filter", raw, sizeof raw)) < 0) return -1;
    if (got && !st_valid_filter(raw, filter)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad filter",
                        "Up to 31 printable characters; * and % are wildcards.", 0, NULL);
        return -1;
    }
    if ((got = svc_query(c, "after", raw, sizeof raw)) < 0) return -1;
    if (got && *raw && !check(raw, after)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad cursor", "after is not a valid name.", 0, NULL);
        return -1;
    }
    if ((got = svc_query(c, "limit", raw, sizeof raw)) < 0) return -1;
    if (got) {
        char *end;
        long n = strtol(raw, &end, 10);
        if (!*raw || *end || n < 1 || n > LIMIT_MAX) {
            st_resp_problem(c->resp, 400, "bad-request", "Bad limit", "limit is 1 to 200.", 0, NULL);
            return -1;
        }
        *limit = (int) n;
    }
    return 0;
}

static void ktime(st_jw *w, const char *key, long long t)
{
    st_jw_key(w, key);
    if (t > 0) st_jw_int(w, t); else st_jw_null(w);
}

static void flags_json(st_jw *w, unsigned int flags)
{
    int i;
    st_jw_key(w, "flags");
    st_jw_arr(w);
    for (i = 0; i < ST_UF_COUNT; i++)
        if (flags & (1u << i)) st_jw_str(w, flag_names[i]);
    st_jw_arr_end(w);
}

/* The hours (0-23) whose bit is set: hours with no access. */
static void hours_json(st_jw *w, const char *key, unsigned int mask)
{
    int h;
    st_jw_key(w, key);
    st_jw_arr(w);
    for (h = 0; h < 24; h++)
        if (mask & (1u << h)) st_jw_int(w, h);
    st_jw_arr_end(w);
}

/* The fields a list row needs. */
static void brief_json(st_jw *w, const st_user *u)
{
    char uic[24];
    svc_uic_text(u->uic, uic);
    st_jw_kstr(w, "username", u->username);
    st_jw_kstr(w, "owner", u->owner);
    st_jw_kstr(w, "account", u->account);
    st_jw_kstr(w, "uic", uic);
    flags_json(w, u->flags);
    ktime(w, "expiration", u->expiration);
    ktime(w, "last_login_interactive", u->last_login_i);
    ktime(w, "last_login_noninteractive", u->last_login_n);
}

/* ---------------------------------------------------------------- list */

typedef struct {
    st_ctx      *c;
    st_jw       *w;
    const char  *filter;
    int          wild;       /* the filter is a wildcard on the username alone */
    int          limit, count;
    char         last[13];
    int          more;       /* another match exists past the page */
    st_err       err;
    int          failed;
} list_state;

static int list_one(const char *username, void *ctx)
{
    list_state *s = ctx;
    st_user u;
    st_err e;
    int got;

    if (s->wild && !st_wild_match(s->filter, username)) return 0;
    got = st_plat_user_get(username, &u, &e) == 0;
    if (!got && e.kind != ST_E_NOPRIV) {   /* anything but a refusal ends the list */
        s->err = e;
        s->failed = 1;
        return 1;
    }
    /* Refused: the name is all we know (the persona could read SYSUAF but not this
       record), so the owner filter cannot apply to it. */
    if (!s->wild && !st_filter_match(s->filter, username, got ? u.owner : NULL)) return 0;
    if (s->count == s->limit) { s->more = 1; return 1; }
    st_jw_obj(s->w);
    if (got) {
        brief_json(s->w, &u);
    } else {
        st_jw_kstr(s->w, "username", username);
        st_jw_kbool(s->w, "restricted", 1);
    }
    st_jw_obj_end(s->w);
    st_copy(s->last, sizeof s->last, username);
    s->count++;
    return 0;
}

/* GET api/v1/users?filter=&after=&limit= */
void svc_users_list(st_ctx *c)
{
    char filter[32], after[32];
    list_state s;
    st_jw w;
    st_err e;

    memset(&s, 0, sizeof s);
    if (svc_list_query(c, filter, after, &s.limit, check_username)) return;
    s.c = c;
    s.w = &w;
    s.filter = filter;
    s.wild = strchr(filter, '*') || strchr(filter, '%');

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "users");
    st_jw_arr(&w);
    if (st_plat_user_enum(after, list_one, &s, &e)) { st_app_error(c, &e); return; }
    if (s.failed) { st_app_error(c, &s.err); return; }
    st_jw_arr_end(&w);
    if (s.more) st_jw_kstr(&w, "next", s.last);
    else { st_jw_key(&w, "next"); st_jw_null(&w); }
    st_jw_obj_end(&w);
}

/* ---------------------------------------------------------------- detail */

static int user_arg(st_ctx *c, char user[13])
{
    if (!st_valid_username(c->args[0], user)) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "Not a valid username.", 0, NULL);
        return -1;
    }
    return 0;
}

/* GET api/v1/users/{u} */
void svc_user_get(st_ctx *c)
{
    char name[13];
    st_user u;
    st_err e;
    st_jw w;
    int i;

    char etag[40];

    if (user_arg(c, name)) return;
    if (st_plat_user_get(name, &u, &e)) { st_app_error(c, &e); return; }
    svc_user_etag(&u, etag);

    st_resp_json(c->resp, 200, &w);
    st_resp_header(c->resp, "ETag", etag);   /* PATCH sends it back as If-Match */
    st_jw_obj(&w);
    brief_json(&w, &u);
    st_jw_kstr(&w, "etag", etag);
    st_jw_kstr(&w, "cli", u.cli);
    st_jw_kstr(&w, "clitables", u.clitables);
    st_jw_kstr(&w, "default_device", u.defdev);
    st_jw_kstr(&w, "default_directory", u.defdir);
    st_jw_kstr(&w, "lgicmd", u.lgicmd);

    st_jw_key(&w, "password");
    st_jw_obj(&w);
    st_jw_kbool(&w, "pre_expired", u.pwd_date == -1);
    ktime(&w, "changed", u.pwd_date);
    ktime(&w, "secondary_changed", u.pwd2_date);
    st_jw_key(&w, "lifetime_days");
    if (u.pwd_lifetime > 0) st_jw_int(&w, u.pwd_lifetime / 86400); else st_jw_null(&w);
    st_jw_kint(&w, "minimum_length", u.pwd_minimum);
    st_jw_kint(&w, "login_failures", u.login_fails);
    st_jw_obj_end(&w);

    st_jw_key(&w, "secondary_days");
    st_jw_arr(&w);
    for (i = 0; i < 7; i++)
        if (u.secondary_days & (1u << i)) st_jw_str(&w, svc_day_names[i]);
    st_jw_arr_end(&w);

    /* Hours with no access, by kind of login: what AUTHORIZE draws as a grid. */
    st_jw_key(&w, "restricted_hours");
    st_jw_obj(&w);
    for (i = 0; i < ST_ACC_COUNT; i++) {
        st_jw_key(&w, svc_access_names[i]);
        st_jw_obj(&w);
        hours_json(&w, "primary", u.access_p[i]);
        hours_json(&w, "secondary", u.access_s[i]);
        st_jw_obj_end(&w);
    }
    st_jw_obj_end(&w);

    svc_privs_json(&w, "authorized_privileges", u.priv_auth);
    svc_privs_json(&w, "default_privileges", u.priv_def);

    st_jw_key(&w, "quotas");
    st_jw_obj(&w);
    for (i = 0; i < ST_Q_COUNT; i++) st_jw_kint(&w, svc_quota_names[i], (long long) u.quota[i]);
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}

/* ---------------------------------------------------------------- held */

typedef struct { st_jw *w; int count; } held_state;

static int held_one(const st_ident *id, void *ctx)
{
    held_state *s = ctx;
    char v[24];
    if (s->count++ >= 4096) return 1;
    svc_ident_value_text(id->value, v);
    st_jw_obj(s->w);
    st_jw_kstr(s->w, "name", id->name);
    st_jw_kstr(s->w, "value", v);
    svc_ident_attrib_json(s->w, "attributes", id->attrib);
    st_jw_obj_end(s->w);
    return 0;
}

/* GET api/v1/users/{u}/identifiers: the identifiers the user holds, with the
   attributes of each holding. The UIC comes from the user's UIC identifier, not
   from $GETUAI: OpenVMS lets anyone read the rights database's holder records
   (PHASE2.md), so $FIND_HELD alone decides, as SHOW/IDENTIFIER does. */
void svc_user_identifiers(st_ctx *c)
{
    char name[13];
    st_ident uic;
    st_err e;
    st_jw w;
    held_state s;

    if (user_arg(c, name)) return;
    if (st_plat_ident_get(name, &uic, &e)) { st_app_error(c, &e); return; }
    if (uic.value & ST_IDENT_GENERAL) {   /* a general identifier, not a user */
        st_resp_problem(c->resp, 404, "not-found", "Not found", "No such user.", 0, NULL);
        return;
    }
    s.count = 0;
    s.w = &w;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "username", name);
    st_jw_key(&w, "identifiers");
    st_jw_arr(&w);
    if (st_plat_ident_held(uic.value, held_one, &s, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}
