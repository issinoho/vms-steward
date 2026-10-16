/* svc_edit.c - changes to users and rights identifiers (Phase 3).

   As everywhere, OpenVMS decides who may change what: each call runs under the
   caller's persona (D2), and a refusal is passed on with the system's message. What
   Steward adds is input discipline:
     - every field is validated, and anything unknown, too long or out of range is
       refused, never trimmed or ignored (security.md);
     - a user edit must name the version it was based on (If-Match: the ETag from
       GET), so two administrators cannot silently overwrite each other;
     - a holding attribute the identifier lacks is refused: OpenVMS would accept it
       and drop it silently (PHASE3.md, finding 4);
     - every change is audited, with what changed, and never a password.
   Passwords are scrubbed with st_zero on every path. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

/* 422 invalid-value, with a detail naming the field. The format attribute makes GCC
   check every caller's format string, which is always a literal, so the vsnprintf
   below can never see one from a request (D8; CI's flawfinder cannot tell). */
#ifdef __GNUC__
static void TOO(st_ctx *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));  /* flawfinder: ignore */
#endif
static void TOO(st_ctx *c, const char *fmt, ...)
{
    char d[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(d, sizeof d, fmt, ap);   /* flawfinder: ignore */
    va_end(ap);
    st_resp_problem(c->resp, 422, "invalid-value", "Invalid value", d, 0, NULL);
}

/* ---------------------------------------------------------------- ETag */

void svc_user_etag(const st_user *u, char out[40])
{
    st_buf b;
    unsigned char h[32];
    char hex[33];   /* 16 bytes of the hash are plenty to tell versions apart */
    int i;
    st_buf_init(&b, 0);
    /* Every field a PATCH can change. Not the last-login times or the failure count,
       which change whenever the user logs in, nor the password dates. */
    st_buf_printf(&b, "%s|%s|%u|%u|%s|%s|%s|%s|%s|%lld|%lld|%d|%u|", u->owner, u->account,
                  u->uic, u->flags, u->cli, u->clitables, u->defdev, u->defdir, u->lgicmd,
                  u->expiration, u->pwd_lifetime, u->pwd_minimum, u->secondary_days);
    for (i = 0; i < ST_ACC_COUNT; i++) st_buf_printf(&b, "%u,%u|", u->access_p[i], u->access_s[i]);
    st_buf_printf(&b, "%u,%u,%u,%u|", u->priv_auth[0], u->priv_auth[1], u->priv_def[0], u->priv_def[1]);
    for (i = 0; i < ST_Q_COUNT; i++) st_buf_printf(&b, "%lu,", u->quota[i]);
    st_plat_sha256(b.data, b.len, h);
    st_buf_free(&b);
    st_hex(h, 16, hex);
    snprintf(out, 40, "\"%s\"", hex);
}

/* ---------------------------------------------------------------- input helpers */

/* A string member into Latin-1 out[size]: printable, at most size-1 characters. -1
   with the 422 set. no_space: also refuse blanks (device, directory, CLI names). */
static int text_value(st_ctx *c, const st_jval *v, const char *key, char *out, size_t size,
                      int no_space)
{
    size_t i, n;
    if (v->type != ST_JSTR || st_json_latin1(v->str, v->slen, out, size)) {
        TOO(c, "%s: a string of at most %u characters", key, (unsigned) (size - 1));
        return -1;
    }
    n = strlen(out);
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char) out[i];
        if (ch < 0x20 || (ch >= 0x7F && ch < 0xA0) || (no_space && ch == ' ')) {
            TOO(c, "%s: control characters%s are not allowed", key, no_space ? " and spaces" : "");
            return -1;
        }
    }
    return 0;
}

static int int_value(st_ctx *c, const st_jval *v, const char *key, long long lo, long long hi,
                     long long *out)
{
    if (v->type != ST_JNUM || v->num != (double) (long long) v->num || v->num < (double) lo ||
        v->num > (double) hi) {
        TOO(c, "%s: a whole number from %lld to %lld", key, lo, hi);
        return -1;
    }
    *out = (long long) v->num;
    return 0;
}

/* A list of names into a bit mask, with lookup(name) giving the bit. */
static int names_value(st_ctx *c, const st_jval *v, const char *key, int (*lookup)(const char *),
                       unsigned int mask[2])
{
    const st_jval *x;
    mask[0] = mask[1] = 0;
    if (v->type != ST_JARR) { TOO(c, "%s: a list of names", key); return -1; }
    for (x = v->child; x; x = x->next) {
        int bit = x->type == ST_JSTR ? lookup(x->str) : -1;
        if (bit < 0 || bit > 63) {
            TOO(c, "%s: unknown name %.40s", key, x->type == ST_JSTR ? x->str : "(not a string)");
            return -1;
        }
        mask[bit / 32] |= 1u << (bit % 32);
    }
    return 0;
}

static int day_bit(const char *name) { return svc_name_index(svc_day_names, 7, name); }

/* Hours 0-23 into a 24-bit mask. */
static int hours_value(st_ctx *c, const st_jval *v, const char *key, unsigned int *mask)
{
    const st_jval *x;
    *mask = 0;
    if (v->type != ST_JARR) { TOO(c, "%s: a list of hours, 0 to 23", key); return -1; }
    for (x = v->child; x; x = x->next) {
        if (x->type != ST_JNUM || x->num != (double) (int) x->num || x->num < 0 || x->num > 23) {
            TOO(c, "%s: hours are whole numbers from 0 to 23", key);
            return -1;
        }
        *mask |= 1u << (int) x->num;
    }
    return 0;
}

static int body_object(st_ctx *c, st_jdoc *doc)
{
    if (st_app_body(c, doc)) return -1;
    if (!doc->root || doc->root->type != ST_JOBJ) {
        st_json_free(doc);
        st_resp_problem(c->resp, 400, "bad-request", "The body must be a JSON object", NULL, 0, NULL);
        return -1;
    }
    return 0;
}

static int user_arg(st_ctx *c, char user[13])
{
    if (!st_valid_username(c->args[0], user)) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "Not a valid username.", 0, NULL);
        return -1;
    }
    return 0;
}

/* Names of the bits that differ, "+A -B", for the audit record. */
static void diff_names(st_buf *b, const char *field, const unsigned int was[2], const unsigned int now[2],
                       const char *(*name)(int))
{
    int bit, any = 0;
    for (bit = 0; bit < 64; bit++) {
        unsigned int w = was[bit / 32] & (1u << (bit % 32)), n = now[bit / 32] & (1u << (bit % 32));
        const char *nm;
        if (w == n || !(nm = name(bit))) continue;
        /* "flags+DISUSER -CAPTIVE" */
        st_buf_printf(b, "%s%s%s%s", any ? " " : (b->len ? "; " : ""), any ? "" : field, n ? "+" : "-", nm);
        any = 1;
    }
}

static const char *flag_name(int bit)
{
    static const char *const names[] = {
        "DISCTLY", "DEFCLI", "LOCKPWD", "RESTRICTED", "DISUSER", "DISWELCOME", "DISNEWMAIL",
        "DISMAIL", "GENPWD", "PWD_EXPIRED", "PWD2_EXPIRED", "AUDIT", "DISREPORT",
        "DISRECONNECT", "AUTOLOGIN", "DISFORCE_PWD_CHANGE", "CAPTIVE", "DISIMAGE",
        "DISPWDDIC", "DISPWDHIS", "DEFCLSVAL", "EXTAUTH", "MIGRATEPWD", "VMSAUTH",
        "DISPWDSYNCH", "PWDMIX" };
    return bit >= 0 && bit < ST_UF_COUNT ? names[bit] : NULL;
}

static void note(st_buf *b, const char *field)
{
    st_buf_printf(b, "%s%s", b->len ? "; " : "", field);
}

/* One member of a user change (PATCH, or the fields of a create), into ch. Returns 0
   if it was a change, 1 if the key is not one (the caller decides), -1 with the 422
   set. base is the record the change applies to: a flag or privilege list is noted
   in what as a difference from it, and restricted_hours starts from its hours. */
static int change_member(st_ctx *c, const st_jval *m, st_user_change *ch, st_buf *what,
                         const st_user *u)
{
    const char *k = m->key;
    long long n;
    if (!strcmp(k, "owner")) {
        if (text_value(c, m, k, ch->owner, sizeof ch->owner, 0)) return -1;
        ch->fields |= ST_UC_OWNER; note(what, k);
    } else if (!strcmp(k, "account")) {
        if (text_value(c, m, k, ch->account, sizeof ch->account, 1)) return -1;
        ch->fields |= ST_UC_ACCOUNT; note(what, k);
    } else if (!strcmp(k, "cli")) {
        if (text_value(c, m, k, ch->cli, sizeof ch->cli, 1)) return -1;
        ch->fields |= ST_UC_CLI; note(what, k);
    } else if (!strcmp(k, "clitables")) {
        if (text_value(c, m, k, ch->clitables, sizeof ch->clitables, 1)) return -1;
        ch->fields |= ST_UC_CLITABLES; note(what, k);
    } else if (!strcmp(k, "default_device")) {
        if (text_value(c, m, k, ch->defdev, sizeof ch->defdev, 1)) return -1;
        ch->fields |= ST_UC_DEFDEV; note(what, k);
    } else if (!strcmp(k, "default_directory")) {
        if (text_value(c, m, k, ch->defdir, sizeof ch->defdir, 1)) return -1;
        ch->fields |= ST_UC_DEFDIR; note(what, k);
    } else if (!strcmp(k, "lgicmd")) {
        if (text_value(c, m, k, ch->lgicmd, sizeof ch->lgicmd, 0)) return -1;
        ch->fields |= ST_UC_LGICMD; note(what, k);
    } else if (!strcmp(k, "flags")) {
        unsigned int f[2], was[2];
        if (names_value(c, m, k, svc_flag_bit, f)) return -1;
        ch->flags = f[0];
        ch->fields |= ST_UC_FLAGS;
        was[0] = u->flags; was[1] = 0;
        diff_names(what, "flags", was, f, flag_name);
    } else if (!strcmp(k, "expiration")) {
        if (m->type == ST_JNULL) ch->expiration = 0;
        else if (int_value(c, m, k, 0, 253402300799LL, &n)) return -1;   /* to 9999 */
        else ch->expiration = n;
        ch->fields |= ST_UC_EXPIRATION; note(what, k);
    } else if (!strcmp(k, "password")) {
        const st_jval *p;
        if (m->type != ST_JOBJ) { TOO(c, "password: an object"); return -1; }
        for (p = m->child; p; p = p->next) {
            if (!strcmp(p->key, "lifetime_days")) {
                if (p->type == ST_JNULL) ch->pwd_lifetime = 0;
                else if (int_value(c, p, "password.lifetime_days", 1, 9999, &n)) return -1;
                else ch->pwd_lifetime = n * 86400;
                ch->fields |= ST_UC_PWD_LIFETIME; note(what, "password lifetime");
            } else if (!strcmp(p->key, "minimum_length")) {
                if (int_value(c, p, "password.minimum_length", 0, 32, &n)) return -1;
                ch->pwd_minimum = (int) n;
                ch->fields |= ST_UC_PWD_MINIMUM; note(what, "password minimum");
            } else {
                TOO(c, "password.%.40s: not something that can be changed here", p->key);
                return -1;
            }
        }
    } else if (!strcmp(k, "secondary_days")) {
        unsigned int d[2];
        if (names_value(c, m, k, day_bit, d)) return -1;
        ch->secondary_days = d[0];
        ch->fields |= ST_UC_DAYS; note(what, k);
    } else if (!strcmp(k, "restricted_hours")) {
        const st_jval *kind, *h;
        int i;
        if (m->type != ST_JOBJ) { TOO(c, "restricted_hours: an object"); return -1; }
        for (i = 0; i < ST_ACC_COUNT; i++) { ch->access_p[i] = u->access_p[i]; ch->access_s[i] = u->access_s[i]; }
        for (kind = m->child; kind; kind = kind->next) {
            int ki = svc_name_index(svc_access_names, ST_ACC_COUNT, kind->key);
            if (ki < 0 || kind->type != ST_JOBJ) {
                TOO(c, "restricted_hours.%.20s: network, batch, local, dialup or remote, each {primary, secondary}", kind->key);
                return -1;
            }
            for (h = kind->child; h; h = h->next) {
                if (!strcmp(h->key, "primary")) { if (hours_value(c, h, "restricted_hours", &ch->access_p[ki])) return -1; }
                else if (!strcmp(h->key, "secondary")) { if (hours_value(c, h, "restricted_hours", &ch->access_s[ki])) return -1; }
                else { TOO(c, "restricted_hours.%s.%.20s: primary or secondary", kind->key, h->key); return -1; }
            }
        }
        ch->fields |= ST_UC_ACCESS; note(what, k);
    } else if (!strcmp(k, "authorized_privileges") || !strcmp(k, "default_privileges")) {
        unsigned int p[2];
        int auth = k[0] == 'a';
        if (names_value(c, m, k, svc_priv_bit, p)) return -1;
        if (auth) { ch->priv_auth[0] = p[0]; ch->priv_auth[1] = p[1]; ch->fields |= ST_UC_PRIV_AUTH; }
        else { ch->priv_def[0] = p[0]; ch->priv_def[1] = p[1]; ch->fields |= ST_UC_PRIV_DEF; }
        diff_names(what, auth ? "authorized" : "default", auth ? u->priv_auth : u->priv_def, p, svc_priv_name);
    } else if (!strcmp(k, "quotas")) {
        /* Ranges from the item sizes: byte, word or longword. */
        static const long long max[ST_Q_COUNT] = { 31, 255, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 4294967295LL, 4294967295LL,
            4294967295LL, 4294967295LL, 4294967295LL, 4294967295LL, 4294967295LL, 4294967295LL };
        const st_jval *q;
        if (m->type != ST_JOBJ) { TOO(c, "quotas: an object"); return -1; }
        for (q = m->child; q; q = q->next) {
            int qi = svc_name_index(svc_quota_names, ST_Q_COUNT, q->key);
            char key[40];
            if (qi < 0) { TOO(c, "quotas.%.20s: not a quota", q->key); return -1; }
            snprintf(key, sizeof key, "quotas.%s", svc_quota_names[qi]);
            if (int_value(c, q, key, 0, max[qi], &n)) return -1;
            ch->quota[qi] = (unsigned long) n;
            ch->quota_mask |= 1u << qi;
            note(what, key);
        }
        if (ch->quota_mask) ch->fields |= ST_UC_QUOTAS;
    } else {
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- PATCH a user */

/* PATCH api/v1/users/{u}, If-Match: <ETag>. Members, all optional:
     owner, account, cli, clitables, default_device, default_directory, lgicmd,
     flags [names], expiration (seconds | null), password {lifetime_days (| null),
     minimum_length}, secondary_days [MON..SUN], restricted_hours {kind: {primary,
     secondary}}, authorized_privileges [names], default_privileges [names],
     quotas {name: n}.
   Lists replace the whole set. Unknown members are refused. */
void svc_user_modify(st_ctx *c)
{
    char user[13], etag[40], audit_target[16];
    const char *want;
    st_user u;
    st_user_change ch;
    st_jdoc doc;
    const st_jval *m;
    st_err e;
    st_buf what;

    if (user_arg(c, user)) return;
    want = st_req_header(c->req, "HTTP_IF_MATCH");
    if (!want || !*want) {
        st_resp_problem(c->resp, 428, "precondition-required", "If-Match required",
                        "Send the ETag from GET, so a change made meanwhile is not overwritten.", 0, NULL);
        return;
    }
    if (st_plat_user_get(user, &u, &e)) { st_app_error(c, &e); return; }
    svc_user_etag(&u, etag);
    if (strcmp(want, etag)) {
        st_resp_problem(c->resp, 412, "changed", "Changed since you read it",
                        "The account was changed after you loaded it. Reload, then make your change again.", 0, NULL);
        st_resp_header(c->resp, "ETag", etag);
        return;
    }
    if (body_object(c, &doc)) return;

    memset(&ch, 0, sizeof ch);
    st_buf_init(&what, 0);
    for (m = doc.root->child; m; m = m->next) {
        int r = change_member(c, m, &ch, &what, &u);
        if (r < 0) goto bad;
        if (r > 0) { TOO(c, "%.40s: not something that can be changed here", m->key); goto bad; }
    }
    st_json_free(&doc);

    st_copy(audit_target, sizeof audit_target, user);
    if (!ch.fields) { st_buf_free(&what); svc_user_get(c); return; }
    if (st_plat_user_modify(user, &ch, &e)) {
        st_app_audit(c, c->session.username, "user-modify", audit_target, "failed", e.text);
        st_buf_free(&what);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "user-modify", audit_target, "ok", st_buf_cstr(&what));
    st_buf_free(&what);
    svc_user_get(c);   /* the record as it now is, with its new ETag */
    return;
bad:
    st_buf_free(&what);
    st_json_free(&doc);
}

/* ---------------------------------------------------------------- passwords */

/* POST api/v1/users/{u}/password {"password": "...", "pre_expired": true|false}:
   an administrator sets a password. The system hashes it and checks the account's
   minimum length. */
void svc_user_set_password(st_ctx *c)
{
    char user[13], pw[80];
    st_jdoc doc;
    const st_jval *v, *pre;
    st_err e;
    int pre_expired = 0;

    if (user_arg(c, user)) return;
    if (body_object(c, &doc)) return;
    v = st_json_get(doc.root, "password");
    pre = st_json_get(doc.root, "pre_expired");
    for (const st_jval *m = doc.root->child; m; m = m->next)
        if (strcmp(m->key, "password") && strcmp(m->key, "pre_expired")) {
            TOO(c, "%.40s: only password and pre_expired", m->key);   /* before the free: */
            st_json_free(&doc);                                       /* m->key is in doc */
            return;
        }
    if (pre && pre->type != ST_JBOOL) { st_json_free(&doc); TOO(c, "pre_expired: true or false"); return; }
    if (pre) pre_expired = pre->boolean;
    if (!v || v->type != ST_JSTR || !v->slen || st_json_latin1(v->str, v->slen, pw, 65) ||
        strlen(pw) > (size_t) st_plat_password_max()) {
        st_json_free(&doc);
        st_zero(pw, sizeof pw);
        TOO(c, "password: 1 to %d characters", st_plat_password_max());
        return;
    }
    st_json_free(&doc);   /* scrubs the decoded password */
    if (st_plat_user_set_password(user, pw, pre_expired, &e)) {
        st_zero(pw, sizeof pw);
        st_app_audit(c, c->session.username, "password-set", user, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_zero(pw, sizeof pw);
    st_app_audit(c, c->session.username, "password-set", user, "ok", pre_expired ? "pre-expired" : NULL);
    c->resp->status = 204;
}

/* POST api/v1/session/password {"username", "current", "new"}: anyone changes their
   own password, signed in or not. That includes the user whose password has expired,
   who cannot sign in until they do.

   The current password is checked first with an ordinary sign-in check: a failure
   there is charged to the client's address, as at sign-in. Only then is
   CHANGE_PASSWORD called, because a failed change is charged to the account and
   would let anyone lock it (PHASE3.md). A wrong username or current password looks
   exactly like a failed sign-in. */
void svc_password_change(st_ctx *c)
{
    st_jdoc doc;
    const char *u8user, *u8cur, *u8new;
    char user[ST_USERNAME_MAX + 1], cur[80], neu[80];
    const char *client = st_valid_ip(c->client) ? c->client : "unknown";
    st_err e;
    int rc;

    if (body_object(c, &doc)) return;
    u8user = st_json_get_str(doc.root, "username");
    u8cur = st_json_get_str(doc.root, "current");
    u8new = st_json_get_str(doc.root, "new");
    if (!u8user || !u8cur || !u8new || !*u8cur || !*u8new) {
        st_json_free(&doc);
        st_resp_problem(c->resp, 400, "bad-request", "username, current and new are required", NULL, 0, NULL);
        return;
    }
    if (!st_valid_username(u8user, user) || st_json_latin1(u8cur, strlen(u8cur), cur, 65)) {
        st_app_audit(c, strlen(u8user) < 40 ? u8user : "-", "password-change", "-", "failed",
                     "malformed username or password");
        st_json_free(&doc);
        st_resp_problem(c->resp, 401, "sign-in-failed", "Sign-in failed", NULL, 0, NULL);
        return;
    }
    if (st_json_latin1(u8new, strlen(u8new), neu, 65) || strlen(neu) > (size_t) st_plat_password_max()) {
        st_json_free(&doc);
        st_zero(cur, sizeof cur); st_zero(neu, sizeof neu);
        TOO(c, "new: at most %d characters, none above U+00FF", st_plat_password_max());
        return;
    }
    st_json_free(&doc);

    rc = st_plat_authenticate(user, cur, client, &e);
    if (rc == ST_AUTH_FAILED) {
        st_zero(cur, sizeof cur); st_zero(neu, sizeof neu);
        st_app_audit(c, user, "password-change", user, "failed", e.text);
        st_resp_problem(c->resp, 401, "sign-in-failed", "Sign-in failed", NULL, 0, NULL);
        return;
    }
    if (rc == ST_AUTH_ERROR) {
        st_zero(cur, sizeof cur); st_zero(neu, sizeof neu);
        st_app_audit(c, user, "password-change", user, "error", e.text);
        st_resp_problem(c->resp, 503, "auth-unavailable", "Sign-in is unavailable", NULL, e.cond, e.text);
        return;
    }
    rc = st_plat_change_password(user, cur, neu, client, &e);
    st_zero(cur, sizeof cur);
    st_zero(neu, sizeof neu);
    if (rc == ST_AUTH_OK) {
        st_app_audit(c, user, "password-change", user, "ok", NULL);
        c->resp->status = 204;
        return;
    }
    st_app_audit(c, user, "password-change", user, rc == ST_AUTH_FAILED ? "refused" : "error", e.text);
    if (rc == ST_AUTH_FAILED)   /* the current password was right: the reason is the user's to see */
        st_resp_problem(c->resp, 422, "password-refused", "The new password was refused",
                        "OpenVMS refused the new password: it may be too short, recently used, or in the dictionary.",
                        e.cond, e.text);
    else
        st_resp_problem(c->resp, 503, "auth-unavailable", "Password change is unavailable", NULL, e.cond, e.text);
}

/* ---------------------------------------------------------------- holdings */

/* The user's UIC, from its UIC identifier (anyone may read it; PHASE2.md). */
static int user_uic(st_ctx *c, const char *user, unsigned int *uic)
{
    st_ident id;
    st_err e;
    if (st_plat_ident_get(user, &id, &e)) { st_app_error(c, &e); return -1; }
    if (id.value & ST_IDENT_GENERAL) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "No such user.", 0, NULL);
        return -1;
    }
    *uic = id.value;
    return 0;
}

static int general_ident(st_ctx *c, const char *raw, st_ident *id)
{
    char name[32];
    st_err e;
    if (!st_valid_ident(raw, name)) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "Not a valid identifier name.", 0, NULL);
        return -1;
    }
    if (st_plat_ident_get(name, id, &e)) { st_app_error(c, &e); return -1; }
    if (!(id->value & ST_IDENT_GENERAL)) {
        st_resp_problem(c->resp, 422, "uic-identifier", "A UIC identifier",
                        "UIC identifiers belong to accounts and cannot be granted or changed here.", 0, NULL);
        return -1;
    }
    return 0;
}

/* Holding attributes must be ones the identifier has: OpenVMS would accept the rest
   and drop them silently (PHASE3.md). */
static int attribs_value(st_ctx *c, const st_jval *v, const st_ident *id, unsigned int *out)
{
    unsigned int a[2];
    if (!v) { *out = 0; return 0; }
    if (names_value(c, v, "attributes", svc_attrib_bit, a)) return -1;
    if (a[0] & ~id->attrib) {
        TOO(c, "attributes: a holding can have only attributes its identifier has; %s has not got all of them", id->name);
        return -1;
    }
    *out = a[0];
    return 0;
}

static void audit_pair(char *out, size_t n, const char *user, const char *ident)
{
    snprintf(out, n, "%s/%s", user, ident);
}

/* POST api/v1/users/{u}/identifiers {"name": "...", "attributes": [...]}: grant. */
void svc_user_grant(st_ctx *c)
{
    char user[13], target[48];
    unsigned int uic, attrib;
    st_ident id;
    st_jdoc doc;
    const char *name;
    st_err e;

    if (user_arg(c, user) || user_uic(c, user, &uic)) return;
    if (body_object(c, &doc)) return;
    name = st_json_get_str(doc.root, "name");
    if (!name) { st_json_free(&doc); TOO(c, "name: the identifier to grant"); return; }
    if (general_ident(c, name, &id) || attribs_value(c, st_json_get(doc.root, "attributes"), &id, &attrib)) {
        st_json_free(&doc);
        return;
    }
    st_json_free(&doc);
    audit_pair(target, sizeof target, user, id.name);
    if (st_plat_holder_add(id.value, uic, attrib, &e)) {
        st_app_audit(c, c->session.username, "grant", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "grant", target, "ok", NULL);
    svc_user_identifiers(c);
    c->resp->status = 201;
}

/* PUT api/v1/users/{u}/identifiers/{id} {"attributes": [...]}: change a holding. */
typedef struct { unsigned int value, attrib; int found; } find_state;
static int find_one(const st_ident *h, void *ctx)
{
    find_state *f = ctx;
    if (h->value == f->value) { f->attrib = h->attrib; f->found = 1; return 1; }
    return 0;
}

void svc_user_holding(st_ctx *c)
{
    char user[13], target[48];
    unsigned int uic, want;
    st_ident id;
    st_jdoc doc;
    find_state f;
    st_err e;

    if (user_arg(c, user) || user_uic(c, user, &uic) || general_ident(c, c->args[1], &id)) return;
    if (body_object(c, &doc)) return;
    if (!st_json_get(doc.root, "attributes")) { st_json_free(&doc); TOO(c, "attributes: the holding's attributes"); return; }
    if (attribs_value(c, st_json_get(doc.root, "attributes"), &id, &want)) { st_json_free(&doc); return; }
    st_json_free(&doc);
    memset(&f, 0, sizeof f);
    f.value = id.value;
    if (st_plat_ident_held(uic, find_one, &f, &e)) { st_app_error(c, &e); return; }
    if (!f.found) {
        st_resp_problem(c->resp, 404, "not-held", "Not held", "The user does not hold that identifier.", 0, NULL);
        return;
    }
    audit_pair(target, sizeof target, user, id.name);
    if (st_plat_holder_modify(id.value, uic, want & ~f.attrib, f.attrib & ~want, &e)) {
        st_app_audit(c, c->session.username, "holding-modify", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "holding-modify", target, "ok", NULL);
    svc_user_identifiers(c);
}

/* DELETE api/v1/users/{u}/identifiers/{id}: revoke. */
void svc_user_revoke(st_ctx *c)
{
    char user[13], target[48];
    unsigned int uic;
    st_ident id;
    st_err e;

    if (user_arg(c, user) || user_uic(c, user, &uic) || general_ident(c, c->args[1], &id)) return;
    audit_pair(target, sizeof target, user, id.name);
    if (st_plat_holder_remove(id.value, uic, &e)) {
        st_app_audit(c, c->session.username, "revoke", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "revoke", target, "ok", NULL);
    c->resp->status = 204;
}

/* ---------------------------------------------------------------- identifiers */

static void ident_out(st_ctx *c, const char *name, int status)
{
    st_ident id;
    st_err e;
    st_jw w;
    char v[24];
    if (st_plat_ident_get(name, &id, &e)) { st_app_error(c, &e); return; }
    svc_ident_value_text(id.value, v);
    st_resp_json(c->resp, status, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "name", id.name);
    st_jw_kstr(&w, "value", v);
    st_jw_kstr(&w, "type", "general");
    svc_ident_attrib_json(&w, "attributes", id.attrib);
    st_jw_obj_end(&w);
}

/* POST api/v1/identifiers {"name", "value" (optional, "%X8nnnnnnn"), "attributes"}. */
void svc_ident_create(st_ctx *c)
{
    st_jdoc doc;
    const st_jval *m;
    char name[32] = "";
    unsigned int value = 0, attrib = 0, a[2];
    st_ident out;
    st_err e;

    if (body_object(c, &doc)) return;
    for (m = doc.root->child; m; m = m->next) {
        if (!strcmp(m->key, "name")) {
            if (m->type != ST_JSTR || !st_valid_ident(m->str, name)) {
                TOO(c, "name: 1 to 31 characters from A-Z 0-9 _ $, not all digits"); goto bad;
            }
        } else if (!strcmp(m->key, "value")) {
            char *end;
            unsigned long v;
            if (m->type != ST_JSTR || (strncmp(m->str, "%X", 2) && strncmp(m->str, "%x", 2)) ||
                strlen(m->str) != 10 || ((v = strtoul(m->str + 2, &end, 16)), *end) ||
                !(v & ST_IDENT_GENERAL)) {
                TOO(c, "value: %%X followed by 8 hex digits, with the top bit set (a general identifier)");
                goto bad;
            }
            value = (unsigned int) v;
        } else if (!strcmp(m->key, "attributes")) {
            if (names_value(c, m, "attributes", svc_attrib_bit, a)) goto bad;
            attrib = a[0];
        } else {
            TOO(c, "%.40s: only name, value and attributes", m->key);
            goto bad;
        }
    }
    st_json_free(&doc);
    if (!*name) { TOO(c, "name is required"); return; }
    if (st_plat_ident_add(name, value, attrib, &out, &e)) {
        st_app_audit(c, c->session.username, "ident-create", name, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "ident-create", name, "ok", NULL);
    ident_out(c, name, 201);
    return;
bad:
    st_json_free(&doc);
}

/* PATCH api/v1/identifiers/{id} {"name": new name, "attributes": [the whole set]}. */
void svc_ident_modify(st_ctx *c)
{
    st_ident id;
    st_jdoc doc;
    const st_jval *m;
    char newname[32] = "", detail[120];
    unsigned int attrib, a[2];
    int have_attr = 0;
    st_err e;

    if (general_ident(c, c->args[0], &id)) return;
    attrib = id.attrib;
    if (body_object(c, &doc)) return;
    for (m = doc.root->child; m; m = m->next) {
        if (!strcmp(m->key, "name")) {
            if (m->type != ST_JSTR || !st_valid_ident(m->str, newname)) {
                TOO(c, "name: 1 to 31 characters from A-Z 0-9 _ $, not all digits"); goto bad;
            }
        } else if (!strcmp(m->key, "attributes")) {
            if (names_value(c, m, "attributes", svc_attrib_bit, a)) goto bad;
            attrib = a[0];
            have_attr = 1;
        } else {
            TOO(c, "%.40s: only name and attributes", m->key);
            goto bad;
        }
    }
    st_json_free(&doc);
    if (!strcmp(newname, id.name)) newname[0] = '\0';
    snprintf(detail, sizeof detail, "%s%s%s", *newname ? "renamed to " : "", newname,
             have_attr && attrib != id.attrib ? (*newname ? "; attributes" : "attributes") : "");
    if (!*newname && attrib == id.attrib) { ident_out(c, id.name, 200); return; }
    if (st_plat_ident_modify(id.value, newname, attrib & ~id.attrib, id.attrib & ~attrib, &e)) {
        st_app_audit(c, c->session.username, "ident-modify", id.name, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "ident-modify", id.name, "ok", detail);
    ident_out(c, *newname ? newname : id.name, 200);
    return;
bad:
    st_json_free(&doc);
}

static int count_one(const st_ident *h, void *ctx) { (void) h; (*(int *) ctx)++; return 0; }

/* DELETE api/v1/identifiers/{id}: its holdings go with it, as with AUTHORIZE. */
void svc_ident_delete(st_ctx *c)
{
    st_ident id;
    st_err e;
    char detail[64];
    int holders = 0;

    if (general_ident(c, c->args[0], &id)) return;
    st_plat_ident_holders(id.value, count_one, &holders, &e);
    snprintf(detail, sizeof detail, "had %d holder%s", holders, holders == 1 ? "" : "s");
    if (st_plat_ident_remove(id.value, &e)) {
        st_app_audit(c, c->session.username, "ident-delete", id.name, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "ident-delete", id.name, "ok", detail);
    c->resp->status = 204;
}

/* ---------------------------------------------------------------- create, copy, delete (Phase 4, D6) */

/* "[g,m]" in octal, as OpenVMS writes a UIC: a group 1-37776 and a member 0-177776
   (177777 is the group's own identifier, not a user). 0 if malformed. */
static unsigned int uic_value(const char *s)
{
    unsigned long g, m;
    char *end;
    if (*s++ != '[') return 0;
    g = strtoul(s, &end, 8);
    if (end == s || *end != ',') return 0;
    s = end + 1;
    m = strtoul(s, &end, 8);
    if (end == s || strcmp(end, "]")) return 0;
    if (g < 1 || g > 037776 || m > 0177776) return 0;
    return (unsigned int) ((g << 16) | m);
}

/* POST api/v1/users: create (template DEFAULT, as AUTHORIZE ADD) or copy (template
   another user, as AUTHORIZE COPY). Members:
     username, uic "[g,m]", password                       required
     template (default "DEFAULT"), pre_expired (default true),
     copy_identifiers, create_directory                     optional
     any member PATCH takes (owner, flags, default_directory, ...), applied over the
     template's values. */
void svc_user_create(st_ctx *c)
{
    st_jdoc doc;
    const st_jval *m;
    st_user_new n;
    st_user base;
    st_err e;
    st_buf what;
    char pw[80], tmpl[13] = "DEFAULT", target[64];
    int have_pw = 0, copy;

    memset(&n, 0, sizeof n);
    n.pre_expired = 1;
    if (body_object(c, &doc)) return;
    st_buf_init(&what, 0);
    /* First the members that say what to create, and from what. */
    for (m = doc.root->child; m; m = m->next) {
        const char *k = m->key;
        if (!strcmp(k, "username")) {
            if (m->type != ST_JSTR || !st_valid_username(m->str, n.username)) {
                TOO(c, "username: 1 to 12 characters from A-Z 0-9 _ $"); goto bad;
            }
        } else if (!strcmp(k, "uic")) {
            if (m->type != ST_JSTR || !(n.uic = uic_value(m->str))) {
                TOO(c, "uic: [group,member] in octal, group 1-37776, member 0-177776"); goto bad;
            }
        } else if (!strcmp(k, "template")) {
            if (m->type != ST_JSTR || !st_valid_username(m->str, tmpl)) { TOO(c, "template: a username"); goto bad; }
        } else if (!strcmp(k, "password")) {
            if (m->type != ST_JSTR || !m->slen || st_json_latin1(m->str, m->slen, pw, 65) ||
                strlen(pw) > (size_t) st_plat_password_max()) {
                TOO(c, "password: 1 to %d characters", st_plat_password_max()); goto bad;
            }
            have_pw = 1;
        } else if (!strcmp(k, "pre_expired") || !strcmp(k, "copy_identifiers") || !strcmp(k, "create_directory")) {
            if (m->type != ST_JBOOL) { TOO(c, "%s: true or false", k); goto bad; }
            if (k[0] == 'p') n.pre_expired = m->boolean;
            else if (k[0] == 'c' && k[1] == 'o') n.copy_identifiers = m->boolean;
            else n.create_directory = m->boolean;
        }
    }
    if (!*n.username || !n.uic || !have_pw) { TOO(c, "username, uic and password are required"); goto bad; }
    st_copy(n.template_user, sizeof n.template_user, tmpl);
    copy = strcmp(tmpl, "DEFAULT") != 0;
    /* Then the fields, as differences from the template's record. */
    if (st_plat_user_get(tmpl, &base, &e)) {
        st_zero(pw, sizeof pw);
        st_buf_free(&what);
        st_json_free(&doc);
        st_app_error(c, &e);
        return;
    }
    for (m = doc.root->child; m; m = m->next) {
        int r;
        if (!strcmp(m->key, "username") || !strcmp(m->key, "uic") || !strcmp(m->key, "template") ||
            !strcmp(m->key, "password") || !strcmp(m->key, "pre_expired") ||
            !strcmp(m->key, "copy_identifiers") || !strcmp(m->key, "create_directory"))
            continue;
        r = change_member(c, m, &n.more, &what, &base);
        if (r < 0) goto bad;
        if (r > 0) { TOO(c, "%.40s: not something a new account can be given", m->key); goto bad; }
    }
    st_json_free(&doc);

    n.password = pw;
    {
        char uic[24];
        svc_uic_text(n.uic, uic);
        snprintf(target, sizeof target, "%s", n.username);
        st_buf_printf(&what, "%sfrom %s, %s%s%s%s", what.len ? "; " : "", tmpl, uic,
                      n.pre_expired ? ", pre-expired" : "", n.copy_identifiers ? ", identifiers copied" : "",
                      n.create_directory ? ", directory" : "");
    }
    if (st_plat_user_create(&n, &e)) {
        st_zero(pw, sizeof pw);
        st_app_audit(c, c->session.username, copy ? "user-copy" : "user-create", target, "failed", e.text);
        st_buf_free(&what);
        st_app_error(c, &e);
        return;
    }
    st_zero(pw, sizeof pw);
    if (*n.warning) st_buf_printf(&what, "; %s", n.warning);
    st_app_audit(c, c->session.username, copy ? "user-copy" : "user-create", target, "ok", st_buf_cstr(&what));
    st_buf_free(&what);
    st_copy(c->args[0], sizeof c->args[0], n.username);
    svc_user_get(c);
    c->resp->status = 201;
    if (*n.warning) st_resp_header(c->resp, "X-Steward-Warning", n.warning);
    return;
bad:
    st_zero(pw, sizeof pw);
    st_buf_free(&what);
    st_json_free(&doc);
}

/* DELETE api/v1/users/{u}, If-Match: <ETag>: as AUTHORIZE REMOVE (the record, its UIC
   identifier and its holdings). Not the account you are signed in as, nor the
   service's own (D6): either would cut Steward off. */
void svc_user_delete(st_ctx *c)
{
    char user[13], etag[40], detail[64];
    const char *want;
    st_user u;
    st_err e;
    int held = 0;

    if (user_arg(c, user)) return;
    if (!strcmp(user, c->session.username) || !strcmp(user, st_plat_service_account())) {
        st_resp_problem(c->resp, 409, "protected-account", "Not this account",
                        !strcmp(user, c->session.username)
                            ? "You cannot delete the account you are signed in as."
                            : "This is Steward's own service account.", 0, NULL);
        return;
    }
    want = st_req_header(c->req, "HTTP_IF_MATCH");
    if (!want || !*want) {
        st_resp_problem(c->resp, 428, "precondition-required", "If-Match required",
                        "Send the ETag from GET, so that you delete the account you looked at.", 0, NULL);
        return;
    }
    if (st_plat_user_get(user, &u, &e)) { st_app_error(c, &e); return; }
    svc_user_etag(&u, etag);
    if (strcmp(want, etag)) {
        st_resp_problem(c->resp, 412, "changed", "Changed since you read it",
                        "The account was changed after you loaded it. Reload it before deleting.", 0, NULL);
        st_resp_header(c->resp, "ETag", etag);
        return;
    }
    st_plat_ident_held(u.uic, count_one, &held, &e);
    snprintf(detail, sizeof detail, "held %d identifier%s", held, held == 1 ? "" : "s");
    if (st_plat_user_delete(user, &e)) {
        st_app_audit(c, c->session.username, "user-delete", user, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "user-delete", user, "ok", detail);
    c->resp->status = 204;
}

/* GET api/v1/uic/next?group=<octal>: the lowest free member of a UIC group, from the
   rights database's UIC identifiers (readable by anyone). A suggestion for the create
   dialog: the create itself still refuses a UIC in use. */
typedef struct { unsigned int group; unsigned char used[8192]; } uic_scan;

static int uic_seen(const st_ident *id, void *ctx)
{
    uic_scan *s = ctx;
    unsigned int m = id->value & 0xFFFF;
    if (!(id->value & ST_IDENT_GENERAL) && (id->value >> 16) == s->group && m < 65536u)
        s->used[m / 8] |= (unsigned char) (1u << (m % 8));
    return 0;
}

void svc_uic_next(st_ctx *c)
{
    static uic_scan s;
    char raw[16], *end, uic[24];
    unsigned long g;
    unsigned int m;
    st_err e;
    st_jw w;

    if (svc_query(c, "group", raw, sizeof raw) != 1 || ((g = strtoul(raw, &end, 8)), *end) ||
        end == raw || g < 1 || g > 037776) {
        st_resp_problem(c->resp, 400, "bad-request", "group: an octal UIC group, 1-37776", NULL, 0, NULL);
        return;
    }
    memset(&s, 0, sizeof s);
    s.group = (unsigned int) g;
    if (st_plat_ident_enum(uic_seen, &s, &e)) { st_app_error(c, &e); return; }
    for (m = 1; m < 0177777u && (s.used[m / 8] & (1u << (m % 8))); m++) ;
    if (m >= 0177777u) {
        st_resp_problem(c->resp, 409, "group-full", "No free member in this group", NULL, 0, NULL);
        return;
    }
    svc_uic_text((s.group << 16) | m, uic);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "uic", uic);
    st_jw_obj_end(&w);
}
