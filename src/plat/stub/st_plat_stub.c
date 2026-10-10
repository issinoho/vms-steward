/* st_plat_stub.c - in-memory platform for Linux tests and front-end work.

   A handful of fixed accounts stand in for SYSUAF, behaving as the x86 probes showed
   the real thing does (docs/PHASE0.md, docs/PHASE1.md):

     STEWARD_ADM    admin-pass     [362,2] defaults TMPMBX, NETMBX, OPER; SYSPRV and
                                   GRPPRV authorized only (the habit D9 respects);
                                   holds STEWARD_DEMO
     STEWARD_TEST   test-pass      [362,1] TMPMBX, NETMBX only, as on the x86 node
     DISABLED       disabled-pass  DISUSER: fails, reason "account is disabled"
     EXPIRED        expired-pass   right password, but expired
     SYSTEM         (none)         [1,4] every privilege; cannot sign in here

   Reading users and identifiers follows what the x86 node showed (PHASE2.md):
   listing SYSUAF needs SYSPRV or READALL; $GETUAI allows your own record, your
   group's with GRPPRV, anyone's with SYSPRV, and says RNF for a user that does not
   exist before it checks privilege; the rights database ($IDTOASC, $FIND_HELD,
   $FIND_HOLDER) is readable by anyone. So STEWARD_ADM can list users only after
   switching SYSPRV on (D9), as at a terminal.

   These are test fixtures, not credentials: nothing here touches a real system.
   Sessions are kept in memory, so the stub serves a single process. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "st_buf.h"
#include "st_platform.h"

#define BIT(n) (1u << (n))

typedef struct {
    const char  *username, *password, *owner, *account;
    unsigned int uic;
    unsigned int priv_auth[2];
    unsigned int priv_def[2];
    int          disabled, expired;
    const char  *ids[4];
} stub_user;

/* Privilege bits as in PRVDEF: TMPMBX 15, NETMBX 20, SYSPRV 28, OPER 18,
   GRPPRV 34 (bit 2 of the second longword). */
static const stub_user users[] = {
    { "STEWARD_ADM", "admin-pass", "Steward admin (stub)", "STEWARD", 0x00F20002u,
      { BIT(15) | BIT(20) | BIT(28) | BIT(18), BIT(2) }, { BIT(15) | BIT(20) | BIT(18), 0 },
      0, 0, { "STEWARD_DEMO", "STEWARD_OPS", NULL } },
    { "STEWARD_TEST", "test-pass", "Steward test (stub)", "STEWARD", 0x00F20001u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 0, 0, { "STEWARD_OPS", NULL } },
    { "DISABLED", "disabled-pass", "Disabled account (stub)", "", 0x00F20003u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 1, 0, { NULL } },
    { "EXPIRED", "expired-pass", "Expired password (stub)", "", 0x00F20004u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 0, 1, { NULL } },
    { "SYSTEM", NULL, "SYSTEM MANAGER", "SYSTEM", 0x00010004u,
      { 0xFFFFFFFFu, 0x7Fu }, { 0xFFFFFFFFu, 0x7Fu }, 0, 0, { NULL } },
};
#define NUSERS (sizeof users / sizeof users[0])

/* General identifiers. Holdings come from the users' ids lists above. */
static const st_ident idents[] = {
    { "STEWARD_DEMO", 0x80010001u, 1u << ST_IA_RESOURCE },
    { "STEWARD_OPS",  0x80010002u, 0 },
    { "BATCH",        0x80000001u, 0 },
    { "INTERACTIVE",  0x80000003u, 0 },
    { "NETWORK",      0x80000005u, 0 },
};
#define NIDENTS (sizeof idents / sizeof idents[0])

/* Condition values the stub reports, so problems carry vms_status as on OpenVMS. */
#define C_NOSYSPRV 0x2964u
#define C_NOSUCHID 0x1CA4u

#define NSESSIONS 256
static st_session sessions[NSESSIONS];
static int        session_used[NSESSIONS];
static const stub_user *persona;
static unsigned int       persona_cur[2];   /* current privileges of the persona */
static FILE      *audit_fp;

static void set_err(st_err *e, int kind, const char *text)
{
    if (!e) return;
    e->kind = kind;
    e->cond = 0;
    strncpy(e->text, text, sizeof e->text - 1);
    e->text[sizeof e->text - 1] = '\0';
}

static const stub_user *find_user(const char *name)
{
    size_t i;
    for (i = 0; i < NUSERS; i++)
        if (!strcmp(users[i].username, name)) return &users[i];
    return NULL;
}

int st_plat_init(const st_plat_config *cfg, st_err *e)
{
    if (cfg && cfg->audit_file && *cfg->audit_file) {
        audit_fp = fopen(cfg->audit_file, "a");
        if (!audit_fp) { set_err(e, ST_E_INTERNAL, "cannot open audit file"); return -1; }
    }
    set_err(e, ST_OK, "");
    return 0;
}

int st_plat_authenticate(const char *username, const char *password,
                         const char *client, st_err *e)
{
    const stub_user *u = find_user(username);
    (void) client;
    if (!u || !u->password || strcmp(u->password, password)) {
        set_err(e, ST_OK, u ? "invalid password" : "no such user");
        return ST_AUTH_FAILED;
    }
    if (u->disabled) { set_err(e, ST_OK, "account is disabled"); return ST_AUTH_FAILED; }
    if (u->expired) { set_err(e, ST_OK, "password has expired"); return ST_AUTH_EXPIRED; }
    set_err(e, ST_OK, "");
    return ST_AUTH_OK;
}

/* As $SETPRV under a persona: defaults, plus what is asked for and authorized. */
int st_plat_persona_set_privs(const unsigned int enable[2], st_err *e)
{
    int i;
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    for (i = 0; i < 2; i++)
        persona_cur[i] = persona->priv_def[i] | (enable[i] & persona->priv_auth[i]);
    return 0;
}

int st_plat_persona_begin(const char *username, const unsigned int enable[2], st_err *e)
{
    const stub_user *u;
    if (persona) { set_err(e, ST_E_INTERNAL, "a persona is already active"); return -1; }
    u = find_user(username);
    if (!u) { set_err(e, ST_E_NOTFOUND, "no such user"); return -1; }
    persona = u;
    return st_plat_persona_set_privs(enable, e);
}

void st_plat_persona_end(void) { persona = NULL; }

int st_plat_persona_active(void) { return persona != NULL; }

int st_plat_privileges_clean(void) { return 1; }   /* the stub has no privileges */

int st_plat_whoami(st_whoami *w, st_err *e)
{
    int i;
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    memset(w, 0, sizeof *w);
    st_copy(w->username, sizeof w->username, persona->username);
    st_copy(w->owner, sizeof w->owner, persona->owner);
    st_copy(w->account, sizeof w->account, persona->account);
    w->uic = persona->uic;
    w->priv_auth[0] = persona->priv_auth[0];
    w->priv_auth[1] = persona->priv_auth[1];
    w->priv_def[0] = persona->priv_def[0];
    w->priv_def[1] = persona->priv_def[1];
    w->priv_cur[0] = persona_cur[0];
    w->priv_cur[1] = persona_cur[1];
    for (i = 0; i < 4 && persona->ids[i]; i++) st_copy(w->ids[w->nids++], sizeof w->ids[0], persona->ids[i]);
    return 0;
}

/* ================================================================ users, identifiers */

static int cur_has(int bit) { return persona && (persona_cur[bit / 32] & (1u << (bit % 32))); }
#define P_SYSPRV  28
#define P_GRPPRV  34
#define P_READALL 35

static int refuse(st_err *e)
{
    set_err(e, ST_E_NOPRIV, "%SYSTEM-F-NOSYSPRV, operation requires SYSPRV privilege");
    e->cond = C_NOSYSPRV;
    return -1;
}

/* SYSUAF is (S:RWED,O:RWED,G,W) and owned by group 1. */
static int may_read_uaf(void)
{
    return cur_has(P_SYSPRV) || cur_has(P_READALL) || (persona && (persona->uic >> 16) == 1);
}

static int cmp_users(const void *a, const void *b)
{
    return strcmp((*(const stub_user *const *) a)->username, (*(const stub_user *const *) b)->username);
}

int st_plat_user_enum(const char *after, st_name_cb fn, void *ctx, st_err *e)
{
    const stub_user *sorted[NUSERS];
    size_t i;
    if (!may_read_uaf()) return refuse(e);
    for (i = 0; i < NUSERS; i++) sorted[i] = &users[i];
    qsort(sorted, NUSERS, sizeof sorted[0], cmp_users);
    for (i = 0; i < NUSERS; i++) {
        if (after && *after && strcmp(sorted[i]->username, after) <= 0) continue;
        if (fn(sorted[i]->username, ctx)) break;
    }
    return 0;
}

int st_plat_user_get(const char *username, st_user *out, st_err *e)
{
    const stub_user *u = find_user(username);
    int i;
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    /* As $GETUAI on the node: a missing record is RNF whoever asks. */
    if (!u) { set_err(e, ST_E_NOTFOUND, "%RMS-E-RNF, record not found"); e->cond = 0x182B2u; return -1; }
    if (!(u == persona || cur_has(P_SYSPRV) ||
          (cur_has(P_GRPPRV) && (u->uic >> 16) == (persona->uic >> 16))))
        return refuse(e);
    memset(out, 0, sizeof *out);
    st_copy(out->username, sizeof out->username, u->username);
    st_copy(out->owner, sizeof out->owner, u->owner);
    st_copy(out->account, sizeof out->account, u->account);
    out->uic = u->uic;
    if (u->disabled) out->flags |= 1u << ST_UF_DISUSER;
    if (u->expired) out->flags |= 1u << ST_UF_PWD_EXPIRED;
    if (!strcmp(u->username, "STEWARD_ADM")) out->flags |= 1u << ST_UF_DISCTLY;
    st_copy(out->cli, sizeof out->cli, "DCL");
    st_copy(out->clitables, sizeof out->clitables, "DCLTABLES");
    st_copy(out->defdev, sizeof out->defdev, "SYS$SYSDEVICE:");
    snprintf(out->defdir, sizeof out->defdir, "[%s]", u->username);
    out->last_login_i = u->password ? 1791700000LL : 0;
    out->pwd_date = u->expired ? -1 : 1791000000LL;
    out->pwd_lifetime = 90LL * 86400;
    out->pwd_minimum = 15;
    out->secondary_days = 0x60;              /* Saturday and Sunday */
    if (!strcmp(u->username, "STEWARD_TEST"))
        out->access_p[ST_ACC_DIALUP] = out->access_s[ST_ACC_DIALUP] = 0xFFFFFFu;   /* no dialup */
    out->priv_auth[0] = u->priv_auth[0]; out->priv_auth[1] = u->priv_auth[1];
    out->priv_def[0] = u->priv_def[0];   out->priv_def[1] = u->priv_def[1];
    {
        static const unsigned long q[ST_Q_COUNT] = { 4, 4, 0, 0, 0, 8, 150, 150, 300, 100, 4000,
            128, 0, 128000, 0, 4096, 4096, 8192, 16384, 256000, 0 };
        for (i = 0; i < ST_Q_COUNT; i++) out->quota[i] = q[i];
    }
    return 0;
}

static const st_ident *find_ident(const char *name)
{
    size_t i;
    for (i = 0; i < NIDENTS; i++)
        if (!strcmp(idents[i].name, name)) return &idents[i];
    return NULL;
}

int st_plat_ident_enum(st_ident_cb fn, void *ctx, st_err *e)
{
    size_t i;
    (void) e;
    for (i = 0; i < NIDENTS; i++)
        if (fn(&idents[i], ctx)) return 0;
    for (i = 0; i < NUSERS; i++) {   /* a UIC identifier for every user */
        st_ident id;
        memset(&id, 0, sizeof id);
        st_copy(id.name, sizeof id.name, users[i].username);
        id.value = users[i].uic;
        if (fn(&id, ctx)) return 0;
    }
    return 0;
}

int st_plat_ident_get(const char *name, st_ident *out, st_err *e)
{
    const st_ident *id = find_ident(name);
    const stub_user *u = find_user(name);
    if (id) { *out = *id; return 0; }
    if (u) {
        memset(out, 0, sizeof *out);
        st_copy(out->name, sizeof out->name, u->username);
        out->value = u->uic;
        return 0;
    }
    set_err(e, ST_E_NOTFOUND, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    e->cond = C_NOSUCHID;
    return -1;
}

int st_plat_ident_held(unsigned int uic, st_ident_cb fn, void *ctx, st_err *e)
{
    size_t i;
    int k;
    (void) e;
    for (i = 0; i < NUSERS; i++) {
        if (users[i].uic != uic) continue;
        for (k = 0; k < 4 && users[i].ids[k]; k++) {
            const st_ident *id = find_ident(users[i].ids[k]);
            if (id) {
                st_ident h = *id;
                h.attrib = 0;
                if (fn(&h, ctx)) return 0;
            }
        }
    }
    return 0;
}

int st_plat_ident_holders(unsigned int value, st_ident_cb fn, void *ctx, st_err *e)
{
    size_t i;
    int k;
    (void) e;
    for (i = 0; i < NUSERS; i++)
        for (k = 0; k < 4 && users[i].ids[k]; k++) {
            const st_ident *id = find_ident(users[i].ids[k]);
            if (id && id->value == value) {
                st_ident h;
                memset(&h, 0, sizeof h);
                st_copy(h.name, sizeof h.name, users[i].username);
                h.value = users[i].uic;
                if (fn(&h, ctx)) return 0;
            }
        }
    return 0;
}

long long st_plat_time(void) { return (long long) time(NULL); }

static int find_session(const unsigned char key[32])
{
    int i;
    for (i = 0; i < NSESSIONS; i++)
        if (session_used[i] && !memcmp(sessions[i].key, key, 32)) return i;
    return -1;
}

int st_plat_session_put(const st_session *s, st_err *e)
{
    int i = find_session(s->key);
    if (i < 0)
        for (i = 0; i < NSESSIONS && session_used[i]; i++) ;
    if (i >= NSESSIONS) { set_err(e, ST_E_INTERNAL, "session table full"); return -1; }
    sessions[i] = *s;
    session_used[i] = 1;
    return 0;
}

int st_plat_session_get(const unsigned char key[32], st_session *s, st_err *e)
{
    int i = find_session(key);
    (void) e;
    if (i < 0) return 0;
    *s = sessions[i];
    return 1;
}

int st_plat_session_delete(const unsigned char key[32], st_err *e)
{
    int i = find_session(key);
    (void) e;
    if (i >= 0) { session_used[i] = 0; memset(&sessions[i], 0, sizeof sessions[i]); }
    return 0;
}

void st_plat_session_purge(long long created_before, long long seen_before)
{
    int i;
    for (i = 0; i < NSESSIONS; i++)
        if (session_used[i] && (sessions[i].created < created_before ||
                                sessions[i].last_seen < seen_before)) {
            session_used[i] = 0;
            memset(&sessions[i], 0, sizeof sessions[i]);
        }
}

void st_plat_audit(const char *line)
{
    FILE *fp = audit_fp ? audit_fp : stderr;
    char ts[32];
    time_t t = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    fprintf(fp, "%s AUDIT %s\n", ts, line);
    fflush(fp);
}

void st_plat_log(const char *line)
{
    fprintf(stderr, "steward: %s\n", line);
}
