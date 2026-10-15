/* st_plat_stub.c - in-memory platform for Linux tests and front-end work.

   A small SYSUAF and RIGHTSLIST that behave as the x86 probes showed the real ones do
   (docs/PHASE0.md to PHASE3.md), including their refusals, their quirks and their
   condition values (from the node's SSDEF):

     STEWARD_ADM    admin-pass     [362,2] defaults TMPMBX, NETMBX, OPER; SYSPRV and
                                   GRPPRV authorized only (the habit D9 respects);
                                   holds STEWARD_DEMO and STEWARD_OPS
     STEWARD_TEST   test-pass      [362,1] TMPMBX, NETMBX only; holds STEWARD_OPS
     DISABLED       disabled-pass  DISUSER: fails, reason "account is disabled"
     EXPIRED        expired-pass   right password, but pre-expired
     SYSTEM         (none)         [1,4] every privilege; cannot sign in here

   Reading: listing SYSUAF needs SYSPRV or READALL (or group 1, its owner); $GETUAI
   allows your own record, your group's with GRPPRV, anyone's with SYSPRV, and says
   RNF for a missing user before it checks privilege; the rights database is readable
   by anyone (PHASE2.md).
   Changing: $SETUAI needs SYSPRV, or GRPPRV for another member of your group, and
   never your own record without one of them (PHASE3.md); the rights database needs
   SYSPRV. A holding's attributes are masked by its identifier's, and removing an
   identifier removes its holdings (PHASE3.md).

   These are test fixtures, not credentials: nothing here touches a real system. All
   state lives in this process, so the stub serves a single process, and tests that
   change it put it back. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "st_buf.h"
#include "st_platform.h"
#include "st_queue.h"
#include "st_route.h"

#define BIT(n) (1u << (n))

/* Condition values, from the x86 node's SSDEF and RMSDEF. */
#define C_NOPRIV    0x0024u
#define C_NOSUCHID  0x21ECu
#define C_DUPIDENT  0x222Cu
#define C_INVPWDLEN 0x2394u
#define C_PWDINHIS  0x0E72u
#define C_NOSYSPRV  0x28E4u
#define C_RNF       0x182B2u
#define C_RMS_PRV   0x1829Au
#define C_NOLOGNAM  0x01BCu   /* SS$_NOLOGNAM 444 */
#define C_NOLOGTAB  0x2294u   /* SS$_NOLOGTAB 8852 */
#define C_IVLOGTAB  0x015Cu   /* SS$_IVLOGTAB 348 (SHOW LOGICAL returns it as a warning, %X158) */
#define C_NOSYSNAM  0x2814u   /* SS$_NOSYSNAM 10260 */
#define C_NONEXPR   0x08E8u   /* SS$_NONEXPR 2280 */
#define C_NOSUCHQUE 0x0004803Au   /* JBC$_NOSUCHQUE 294970 (JBCMSGDEF on the node) */
#define C_NOSUCHJOB 0x00048042u   /* JBC$_NOSUCHJOB 294978 */
#define C_NOSUCHENT 0x000481DAu   /* JBC$_NOSUCHENT 295386: a job by entry number */

typedef struct {
    st_user u;
    char    password[80];   /* "" cannot sign in */
    int     used;
} stub_user;

#define MAXUSERS  16
#define MAXIDENTS 64
#define MAXHOLDS  256
static stub_user users[MAXUSERS];
static st_ident  idents[MAXIDENTS];
static int       nidents;
static struct { unsigned int value, uic, attrib; int used; } holds[MAXHOLDS];

#define NSESSIONS 256
static st_session sessions[NSESSIONS];
static int        session_used[NSESSIONS];
static stub_user *persona;
static unsigned int persona_cur[2];   /* current privileges of the persona */
static FILE      *audit_fp;
static int        seeded;

static void set_err(st_err *e, int kind, const char *text)
{
    if (!e) return;
    e->kind = kind;
    e->cond = 0;
    strncpy(e->text, text, sizeof e->text - 1);
    e->text[sizeof e->text - 1] = '\0';
}

static int fail(st_err *e, int kind, unsigned int cond, const char *text)
{
    set_err(e, kind, text);
    if (e) e->cond = cond;
    return -1;
}

/* ---------------------------------------------------------------- the data */

static void add_user(const char *name, const char *pw, const char *owner, const char *acct,
                     unsigned int uic, unsigned int a0, unsigned int a1, unsigned int d0,
                     unsigned int d1, unsigned int flags, long long pwd_date)
{
    static const unsigned long q[ST_Q_COUNT] = { 4, 4, 0, 0, 0, 8, 150, 150, 300, 100, 4000,
        128, 0, 128000, 0, 4096, 4096, 8192, 16384, 256000, 0 };
    stub_user *s;
    int i;
    for (i = 0; i < MAXUSERS && users[i].used; i++) ;
    if (i == MAXUSERS) return;
    s = &users[i];
    memset(s, 0, sizeof *s);
    s->used = 1;
    st_copy(s->password, sizeof s->password, pw ? pw : "");
    st_copy(s->u.username, sizeof s->u.username, name);
    st_copy(s->u.owner, sizeof s->u.owner, owner);
    st_copy(s->u.account, sizeof s->u.account, acct);
    s->u.uic = uic;
    s->u.flags = flags;
    st_copy(s->u.cli, sizeof s->u.cli, "DCL");
    st_copy(s->u.clitables, sizeof s->u.clitables, "DCLTABLES");
    st_copy(s->u.defdev, sizeof s->u.defdev, "SYS$SYSDEVICE:");
    snprintf(s->u.defdir, sizeof s->u.defdir, "[%s]", name);
    s->u.last_login_i = pw ? 1791700000LL : 0;
    s->u.pwd_date = pwd_date;
    s->u.pwd_lifetime = 90LL * 86400;
    s->u.pwd_minimum = 8;
    s->u.secondary_days = 0x60;   /* Saturday and Sunday */
    s->u.priv_auth[0] = a0; s->u.priv_auth[1] = a1;
    s->u.priv_def[0] = d0;  s->u.priv_def[1] = d1;
    for (i = 0; i < ST_Q_COUNT; i++) s->u.quota[i] = q[i];
}

static void add_ident_raw(const char *name, unsigned int value, unsigned int attrib)
{
    if (nidents == MAXIDENTS) return;
    memset(&idents[nidents], 0, sizeof idents[0]);
    st_copy(idents[nidents].name, sizeof idents[0].name, name);
    idents[nidents].value = value;
    idents[nidents].attrib = attrib;
    nidents++;
}

static void hold_raw(unsigned int value, unsigned int uic, unsigned int attrib)
{
    int i;
    for (i = 0; i < MAXHOLDS && holds[i].used; i++) ;
    if (i == MAXHOLDS) return;
    holds[i].value = value; holds[i].uic = uic; holds[i].attrib = attrib; holds[i].used = 1;
}

static stub_user *find_user(const char *name);

/* Privilege bits as in PRVDEF: TMPMBX 15, OPER 18, NETMBX 20, SYSPRV 28,
   GRPPRV 34 (bit 2 of the second longword). */
static void seed(void)
{
    if (seeded) return;
    seeded = 1;
    /* AUTHORIZE ADD's template: disabled, as on the node (PHASE4.md). */
    add_user("DEFAULT", NULL, "", "", 0x00800080u,
             BIT(15) | BIT(20), 0, BIT(15) | BIT(20), 0, 1u << ST_UF_DISUSER, -1);
    add_user("STEWARD_ADM", "admin-pass", "Steward administrator", "STEWARD", 0x00F20002u,
             BIT(15) | BIT(20) | BIT(28) | BIT(18) | BIT(2) | BIT(8) | BIT(16), BIT(2), BIT(15) | BIT(20) | BIT(18), 0,
             1u << ST_UF_DISCTLY, 1791000000LL);
    add_user("STEWARD_TEST", "test-pass", "Test account", "STEWARD", 0x00F20001u,
             BIT(15) | BIT(20), 0, BIT(15) | BIT(20), 0, 0, 1791000000LL);
    add_user("DISABLED", "disabled-pass", "Disabled account", "", 0x00F20003u,
             BIT(15) | BIT(20), 0, BIT(15) | BIT(20), 0, 1u << ST_UF_DISUSER, 1791000000LL);
    add_user("EXPIRED", "expired-pass", "Expired password", "", 0x00F20004u,
             BIT(15) | BIT(20), 0, BIT(15) | BIT(20), 0, 0, -1);
    add_user("SYSTEM", NULL, "SYSTEM MANAGER", "SYSTEM", 0x00010004u,
             0xFFFFFFFFu, 0x7Fu, 0xFFFFFFFFu, 0x7Fu, 0, 1791000000LL);
    /* Two more, sorted after the fixtures above so no test's expectations move:
       they make the dev server's list (and the screenshots) look like a system. */
    add_user("TCPIP$FTP", NULL, "TCP/IP FTP server", "TCPIP", 0x00F90002u,
             BIT(15) | BIT(20) | BIT(18), 0, BIT(15) | BIT(20), 0,
             (1u << ST_UF_RESTRICTED) | (1u << ST_UF_DISCTLY) | (1u << ST_UF_LOCKPWD), 1791000000LL);
    add_user("WEBMASTER", NULL, "Web content", "WEB", 0x00C80021u,
             BIT(15) | BIT(20), 0, BIT(15) | BIT(20), 0, 0, 1791000000LL);
    st_copy(find_user("DEFAULT")->u.defdir, sizeof users[0].u.defdir, "[USER]");
    find_user("DEFAULT")->u.defdev[0] = '\0';   /* as on the node: "[USER]", no device */
    /* STEWARD_TEST: no dialup access at all, to give the hour grid something to show. */
    {
        stub_user *t = find_user("STEWARD_TEST");   /* by name: positions move as fixtures are added */
        t->u.access_p[ST_ACC_DIALUP] = t->u.access_s[ST_ACC_DIALUP] = 0xFFFFFFu;
        t->u.pwd_minimum = 15;   /* as on the x86 node */
    }
    add_ident_raw("STEWARD_DEMO", 0x80010001u, 1u << ST_IA_RESOURCE);
    add_ident_raw("STEWARD_OPS",  0x80010002u, 0);
    add_ident_raw("BATCH",        0x80000001u, 0);
    add_ident_raw("INTERACTIVE",  0x80000003u, 0);
    add_ident_raw("NETWORK",      0x80000005u, 0);
    hold_raw(0x80010001u, 0x00F20002u, 0);
    hold_raw(0x80010002u, 0x00F20002u, 0);
    hold_raw(0x80010002u, 0x00F20001u, 0);
}

static stub_user *find_user(const char *name)
{
    int i;
    seed();
    for (i = 0; i < MAXUSERS; i++)
        if (users[i].used && !strcmp(users[i].u.username, name)) return &users[i];
    return NULL;
}

static stub_user *user_by_uic(unsigned int uic)
{
    int i;
    for (i = 0; i < MAXUSERS; i++)
        if (users[i].used && users[i].u.uic == uic) return &users[i];
    return NULL;
}

static st_ident *ident_by_value(unsigned int value)
{
    int i;
    for (i = 0; i < nidents; i++)
        if (idents[i].value == value) return &idents[i];
    return NULL;
}

static st_ident *ident_by_name(const char *name)
{
    int i;
    for (i = 0; i < nidents; i++)
        if (!strcmp(idents[i].name, name)) return &idents[i];
    return NULL;
}

static int expired_pwd(const stub_user *s)
{
    return s->u.pwd_date == -1 || (s->u.flags & (1u << ST_UF_PWD_EXPIRED));
}

/* ---------------------------------------------------------------- start-up, sign-in */

int st_plat_init(const st_plat_config *cfg, st_err *e)
{
    seed();
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
    if (!u || !u->password[0] || strcmp(u->password, password)) {
        set_err(e, ST_OK, u ? "invalid password" : "no such user");
        return ST_AUTH_FAILED;
    }
    if (u->u.flags & (1u << ST_UF_DISUSER)) { set_err(e, ST_OK, "account is disabled"); return ST_AUTH_FAILED; }
    if (expired_pwd(u)) { set_err(e, ST_OK, "password has expired"); return ST_AUTH_EXPIRED; }
    set_err(e, ST_OK, "");
    return ST_AUTH_OK;
}

/* ---------------------------------------------------------------- personas */

/* As $SETPRV under a persona: defaults, plus what is asked for and authorized. */
int st_plat_persona_set_privs(const unsigned int enable[2], st_err *e)
{
    int i;
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    for (i = 0; i < 2; i++)
        persona_cur[i] = persona->u.priv_def[i] | (enable[i] & persona->u.priv_auth[i]);
    return 0;
}

int st_plat_persona_begin(const char *username, const unsigned int enable[2], st_err *e)
{
    stub_user *u;
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
    st_copy(w->username, sizeof w->username, persona->u.username);
    st_copy(w->owner, sizeof w->owner, persona->u.owner);
    st_copy(w->account, sizeof w->account, persona->u.account);
    w->uic = persona->u.uic;
    w->priv_auth[0] = persona->u.priv_auth[0];
    w->priv_auth[1] = persona->u.priv_auth[1];
    w->priv_def[0] = persona->u.priv_def[0];
    w->priv_def[1] = persona->u.priv_def[1];
    w->priv_cur[0] = persona_cur[0];
    w->priv_cur[1] = persona_cur[1];
    for (i = 0; i < MAXHOLDS && w->nids < ST_MAX_IDS; i++)
        if (holds[i].used && holds[i].uic == persona->u.uic) {
            const st_ident *id = ident_by_value(holds[i].value);
            if (id) st_copy(w->ids[w->nids++], sizeof w->ids[0], id->name);
        }
    return 0;
}

/* ================================================================ users, identifiers */

static int cur_has(int bit) { return persona && (persona_cur[bit / 32] & (1u << (bit % 32))); }
#define P_SYSNAM  2
#define P_GRPNAM  3
#define P_GROUP   8
#define P_WORLD   16
#define P_SYSPRV  28
#define P_GRPPRV  34
#define P_READALL 35

static int refuse(st_err *e)
{
    return fail(e, ST_E_NOPRIV, C_NOSYSPRV, "%SYSTEM-F-NOSYSPRV, operation requires SYSPRV privilege");
}

/* SYSUAF and RIGHTSLIST are (S:RWED,O:RWED,G,W) and owned by group 1. */
static int system_access(void)
{
    return cur_has(P_SYSPRV) || (persona && (persona->u.uic >> 16) == 1);
}

static int may_read_uaf(void) { return system_access() || cur_has(P_READALL); }

static int cmp_users(const void *a, const void *b)
{
    return strcmp((*(const stub_user *const *) a)->u.username, (*(const stub_user *const *) b)->u.username);
}

int st_plat_user_enum(const char *after, st_name_cb fn, void *ctx, st_err *e)
{
    const stub_user *sorted[MAXUSERS] = { 0 };   /* cppcheck cannot see that only n are read */
    int i, n = 0;
    if (!may_read_uaf()) return fail(e, ST_E_NOPRIV, C_RMS_PRV, "%RMS-E-PRV, insufficient privilege or file protection violation");
    for (i = 0; i < MAXUSERS; i++) if (users[i].used) sorted[n++] = &users[i];
    qsort(sorted, (size_t) n, sizeof sorted[0], cmp_users);
    for (i = 0; i < n; i++) {
        if (after && *after && strcmp(sorted[i]->u.username, after) <= 0) continue;
        if (fn(sorted[i]->u.username, ctx)) break;
    }
    return 0;
}

int st_plat_user_get(const char *username, st_user *out, st_err *e)
{
    const stub_user *u = find_user(username);
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    /* As $GETUAI on the node: a missing record is RNF whoever asks. */
    if (!u) return fail(e, ST_E_NOTFOUND, C_RNF, "%RMS-E-RNF, record not found");
    if (!(u == persona || cur_has(P_SYSPRV) ||
          (cur_has(P_GRPPRV) && (u->u.uic >> 16) == (persona->u.uic >> 16))))
        return refuse(e);
    *out = u->u;
    return 0;
}

/* $SETUAI: SYSPRV, or GRPPRV for another member of the caller's group. Not even
   your own record without one of them (probe_modify). */
static stub_user *writable_user(const char *username, st_err *e)
{
    stub_user *u = find_user(username);
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return NULL; }
    if (!u) { fail(e, ST_E_NOTFOUND, C_RNF, "%RMS-E-RNF, record not found"); return NULL; }
    if (!(cur_has(P_SYSPRV) || (cur_has(P_GRPPRV) && (u->u.uic >> 16) == (persona->u.uic >> 16)))) {
        fail(e, ST_E_NOPRIV, C_NOPRIV, "%SYSTEM-F-NOPRIV, insufficient privilege or object protection violation");
        return NULL;
    }
    return u;
}

int st_plat_user_modify(const char *username, const st_user_change *c, st_err *e)
{
    stub_user *s = writable_user(username, e);
    st_user *u;
    int i;
    if (!s) return -1;
    u = &s->u;
    if (c->fields & ST_UC_OWNER) st_copy(u->owner, sizeof u->owner, c->owner);
    if (c->fields & ST_UC_ACCOUNT) st_copy(u->account, sizeof u->account, c->account);
    if (c->fields & ST_UC_CLI) st_copy(u->cli, sizeof u->cli, c->cli);
    if (c->fields & ST_UC_CLITABLES) st_copy(u->clitables, sizeof u->clitables, c->clitables);
    if (c->fields & ST_UC_DEFDEV) st_copy(u->defdev, sizeof u->defdev, c->defdev);
    if (c->fields & ST_UC_DEFDIR) st_copy(u->defdir, sizeof u->defdir, c->defdir);
    if (c->fields & ST_UC_LGICMD) st_copy(u->lgicmd, sizeof u->lgicmd, c->lgicmd);
    if (c->fields & ST_UC_FLAGS) u->flags = c->flags;
    if (c->fields & ST_UC_EXPIRATION) u->expiration = c->expiration;
    if (c->fields & ST_UC_PWD_LIFETIME) u->pwd_lifetime = c->pwd_lifetime;
    if (c->fields & ST_UC_PWD_MINIMUM) u->pwd_minimum = c->pwd_minimum;
    if (c->fields & ST_UC_DAYS) u->secondary_days = c->secondary_days;
    if (c->fields & ST_UC_ACCESS)
        for (i = 0; i < ST_ACC_COUNT; i++) { u->access_p[i] = c->access_p[i]; u->access_s[i] = c->access_s[i]; }
    if (c->fields & ST_UC_PRIV_AUTH) { u->priv_auth[0] = c->priv_auth[0]; u->priv_auth[1] = c->priv_auth[1]; }
    if (c->fields & ST_UC_PRIV_DEF) { u->priv_def[0] = c->priv_def[0]; u->priv_def[1] = c->priv_def[1]; }
    if (c->fields & ST_UC_QUOTAS)
        for (i = 0; i < ST_Q_COUNT; i++) if (c->quota_mask & (1u << i)) u->quota[i] = c->quota[i];
    return 0;
}

int st_plat_user_set_password(const char *username, const char *password, int pre_expired,
                              st_err *e)
{
    stub_user *s = writable_user(username, e);
    if (!s) return -1;
    if ((int) strlen(password) < s->u.pwd_minimum || strlen(password) > 64)
        return fail(e, ST_E_INVALID, C_INVPWDLEN, "%SYSTEM-F-INVPWDLEN, password length must be between the minimum and 64 characters");
    st_copy(s->password, sizeof s->password, password);
    s->u.pwd_date = pre_expired ? -1 : (long long) time(NULL);
    return 0;
}

/* Called by the service, with no persona, after the current password was checked. */
int st_plat_change_password(const char *username, const char *current, const char *newpw,
                            const char *client, st_err *e)
{
    stub_user *s = find_user(username);
    (void) client;
    if (!s || strcmp(s->password, current)) { set_err(e, ST_OK, "invalid password"); return ST_AUTH_FAILED; }
    if ((int) strlen(newpw) < s->u.pwd_minimum || strlen(newpw) > 64) {
        fail(e, ST_E_INVALID, C_INVPWDLEN, "%SYSTEM-F-INVPWDLEN, password length must be between the minimum and 64 characters");
        return ST_AUTH_FAILED;
    }
    if (!strcmp(newpw, current)) {
        fail(e, ST_E_INVALID, C_PWDINHIS, "%SYSTEM-F-PWDINHIS, password found in history list, please choose another");
        return ST_AUTH_FAILED;
    }
    st_copy(s->password, sizeof s->password, newpw);
    s->u.pwd_date = (long long) time(NULL);
    s->u.flags &= ~(1u << ST_UF_PWD_EXPIRED);
    set_err(e, ST_OK, "");
    return ST_AUTH_OK;
}

/* ---------------------------------------------------------------- rights database */

int st_plat_ident_enum(st_ident_cb fn, void *ctx, st_err *e)
{
    int i;
    (void) e;
    seed();
    for (i = 0; i < nidents; i++)
        if (fn(&idents[i], ctx)) return 0;
    for (i = 0; i < MAXUSERS; i++) {   /* a UIC identifier for every user */
        st_ident id;
        if (!users[i].used) continue;
        memset(&id, 0, sizeof id);
        st_copy(id.name, sizeof id.name, users[i].u.username);
        id.value = users[i].u.uic;
        if (fn(&id, ctx)) return 0;
    }
    return 0;
}

int st_plat_ident_get(const char *name, st_ident *out, st_err *e)
{
    const st_ident *id = ident_by_name(name);
    const stub_user *u = find_user(name);
    if (id) { *out = *id; return 0; }
    if (u) {
        memset(out, 0, sizeof *out);
        st_copy(out->name, sizeof out->name, u->u.username);
        out->value = u->u.uic;
        return 0;
    }
    return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
}

/* What $FIND_HELD and $FIND_HOLDER report: the holding masked by the identifier. */
static unsigned int effective(unsigned int value, unsigned int attrib)
{
    const st_ident *id = ident_by_value(value);
    return id ? attrib & id->attrib : 0;
}

int st_plat_ident_held(unsigned int uic, st_ident_cb fn, void *ctx, st_err *e)
{
    int i;
    (void) e;
    for (i = 0; i < MAXHOLDS; i++) {
        const st_ident *id;
        st_ident h;
        if (!holds[i].used || holds[i].uic != uic || !(id = ident_by_value(holds[i].value))) continue;
        h = *id;
        h.attrib = effective(holds[i].value, holds[i].attrib);
        if (fn(&h, ctx)) return 0;
    }
    return 0;
}

int st_plat_ident_holders(unsigned int value, st_ident_cb fn, void *ctx, st_err *e)
{
    int i;
    (void) e;
    for (i = 0; i < MAXHOLDS; i++) {
        const stub_user *u;
        st_ident h;
        if (!holds[i].used || holds[i].value != value) continue;
        memset(&h, 0, sizeof h);
        u = user_by_uic(holds[i].uic);
        if (u) st_copy(h.name, sizeof h.name, u->u.username);
        h.value = holds[i].uic;
        h.attrib = effective(value, holds[i].attrib);
        if (fn(&h, ctx)) return 0;
    }
    return 0;
}

static int rdb_writable(st_err *e)
{
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return 0; }
    if (!system_access()) {
        fail(e, ST_E_NOPRIV, C_RMS_PRV, "%RMS-E-PRV, insufficient privilege or file protection violation");
        return 0;
    }
    return 1;
}

int st_plat_ident_add(const char *name, unsigned int value, unsigned int attrib,
                      st_ident *out, st_err *e)
{
    unsigned int v = value;
    if (!rdb_writable(e)) return -1;
    if (ident_by_name(name) || find_user(name) || (v && ident_by_value(v)))
        return fail(e, ST_E_CONFLICT, C_DUPIDENT, "%SYSTEM-F-DUPIDENT, duplicate identifier");
    if (nidents == MAXIDENTS) return fail(e, ST_E_INTERNAL, 0, "stub rights database full");
    if (!v) for (v = 0x80010010u; ident_by_value(v); v++) ;   /* the next free, as on the node */
    add_ident_raw(name, v, attrib);
    *out = idents[nidents - 1];
    return 0;
}

int st_plat_ident_modify(unsigned int value, const char *new_name, unsigned int set,
                         unsigned int clear, st_err *e)
{
    st_ident *id;
    if (!rdb_writable(e)) return -1;
    if (!(id = ident_by_value(value))) return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    if (new_name && *new_name && strcmp(new_name, id->name)) {
        if (ident_by_name(new_name) || find_user(new_name))
            return fail(e, ST_E_CONFLICT, C_DUPIDENT, "%SYSTEM-F-DUPIDENT, duplicate identifier");
        st_copy(id->name, sizeof id->name, new_name);
    }
    id->attrib = (id->attrib | set) & ~clear;
    return 0;
}

int st_plat_ident_remove(unsigned int value, st_err *e)
{
    int i;
    if (!rdb_writable(e)) return -1;
    for (i = 0; i < nidents && idents[i].value != value; i++) ;
    if (i == nidents) return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    memmove(&idents[i], &idents[i + 1], (size_t) (nidents - i - 1) * sizeof idents[0]);
    nidents--;
    for (i = 0; i < MAXHOLDS; i++)   /* the holdings go too (probe_modify) */
        if (holds[i].used && holds[i].value == value) holds[i].used = 0;
    return 0;
}

static int find_hold(unsigned int value, unsigned int uic)
{
    int i;
    for (i = 0; i < MAXHOLDS; i++)
        if (holds[i].used && holds[i].value == value && holds[i].uic == uic) return i;
    return -1;
}

int st_plat_holder_add(unsigned int value, unsigned int uic, unsigned int attrib, st_err *e)
{
    if (!rdb_writable(e)) return -1;
    if (!ident_by_value(value)) return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    if (find_hold(value, uic) >= 0) return fail(e, ST_E_CONFLICT, C_DUPIDENT, "%SYSTEM-F-DUPIDENT, duplicate identifier");
    hold_raw(value, uic, attrib);
    return 0;
}

int st_plat_holder_modify(unsigned int value, unsigned int uic, unsigned int set,
                          unsigned int clear, st_err *e)
{
    int i;
    if (!rdb_writable(e)) return -1;
    if ((i = find_hold(value, uic)) < 0) return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    holds[i].attrib = (holds[i].attrib | set) & ~clear;
    return 0;
}

int st_plat_holder_remove(unsigned int value, unsigned int uic, st_err *e)
{
    int i;
    if (!rdb_writable(e)) return -1;
    if ((i = find_hold(value, uic)) < 0) return fail(e, ST_E_NOTFOUND, C_NOSUCHID, "%SYSTEM-F-NOSUCHID, unknown rights identifier");
    holds[i].used = 0;
    return 0;
}

/* ================================================================ the system */

/* A small x86-64 system, as the dashboard would see it. The idle counter runs with
   the clock at about 12% busy, so two readings give a moving CPU figure. */
int st_plat_system(st_system *s, st_err *e)
{
    long long now = (long long) time(NULL);
    static const struct { const char *dev, *label, *lv; double gb, freegb; int sys; } disks[] = {
        { "DKA0:", "X86SYS", "DISK$X86SYS", 31.9, 11.4, 1 },
        { "DKA100:", "USERS", "DISK$USERS", 63.9, 41.7, 0 },
        { "DKB0:", "DATA", "DISK$DATA", 15.9, 9.2, 0 },
    };
    static const struct { const char *u; unsigned n; } who[] = {
        { "SYSTEM", 1 }, { "STEWARD_ADM", 2 }, { "WEBMASTER", 1 },
    };
    size_t i;
    (void) e;
    seed();
    memset(s, 0, sizeof *s);
    st_copy(s->node, sizeof s->node, "X86VMS");
    st_copy(s->version, sizeof s->version, "E9.2-4");
    st_copy(s->arch, sizeof s->arch, "x86_64");
    st_copy(s->hardware, sizeof s->hardware, "QEMU Standard PC (Q35 + ICH9, 2009)");
    s->virtual_machine = 1;
    s->boot_time = now - (3 * 86400 + 5 * 3600 + 17 * 60);
    s->cpus_active = s->cpus_available = 4;
    s->sampled_at_ms = now * 1000;
    s->cpu_idle_ticks = (unsigned long long) (s->sampled_at_ms / 10 * 4 * 0.88);
    s->load_current = 1; s->load_computable = 0; s->load_computable_out = 0;
    s->mem_total = 8ull << 30;
    s->mem_free = 5368709120ull;
    s->mem_modified = 268435456ull;
    s->page_total = 2ull << 30;
    s->page_used = 113246208ull;
    for (i = 0; i < sizeof disks / sizeof disks[0]; i++) {
        st_disk *d = &s->disks[s->ndisks++];
        st_copy(d->device, sizeof d->device, disks[i].dev);
        st_copy(d->label, sizeof d->label, disks[i].label);
        st_copy(d->logical_volume, sizeof d->logical_volume, disks[i].lv);
        st_copy(d->filesystem, sizeof d->filesystem, "ODS-5");
        d->total = (unsigned long long) (disks[i].gb * 1073741824.0);
        d->free = (unsigned long long) (disks[i].freegb * 1073741824.0);
        d->system_disk = disks[i].sys;
    }
    /* As $GETJPI under a persona: without WORLD, other groups' processes are hidden. */
    if (cur_has(16)) { s->processes = 58; s->processes_hidden = 0; }   /* WORLD */
    else { s->processes = 41; s->processes_hidden = 17; }
    for (i = 0; i < sizeof who / sizeof who[0]; i++) {
        st_copy(s->sessions[s->nsessions].username, sizeof s->sessions[0].username, who[i].u);
        s->sessions[s->nsessions++].sessions = who[i].n;
    }
    s->queues = 4; s->queues_batch = 2; s->queues_output = 2; s->queues_stopped = 1;
    s->jobs_executing = 1; s->jobs_pending = 0; s->jobs_holding = 2; s->jobs_timed = 1;
    s->cluster_member = 0;
    return 0;
}

/* ---------------------------------------------------------------- create and delete (D6) */

const char *st_plat_service_account(void) { return "STEWARD"; }
const char *st_plat_service_image(void) { return "STEWARD.EXE"; }
unsigned int st_plat_max_sys_group(void) { return 8; }   /* SYSGEN's default, x86's */

static int ident_value_used(unsigned int v)
{
    return ident_by_value(v) || user_by_uic(v);
}

int st_plat_user_create(st_user_new *n, st_err *e)
{
    stub_user *t, *u;
    int i;
    n->warning[0] = '\0';
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    if (!system_access()) return fail(e, ST_E_NOPRIV, C_RMS_PRV, "%RMS-E-PRV, insufficient privilege or file protection violation");
    if (find_user(n->username)) return fail(e, ST_E_CONFLICT, 0x184ECu, "%RMS-E-DUP, duplicate key detected (DUP not set)");
    if (ident_by_name(n->username)) return fail(e, ST_E_CONFLICT, C_DUPIDENT, "%SYSTEM-F-DUPIDENT, duplicate identifier");
    if (ident_value_used(n->uic)) return fail(e, ST_E_CONFLICT, C_DUPIDENT, "the UIC is already in use");
    if (!(t = find_user(n->template_user))) return fail(e, ST_E_NOTFOUND, C_RNF, "%RMS-E-RNF, record not found");
    if ((int) strlen(n->password) < t->u.pwd_minimum || strlen(n->password) > 64)
        return fail(e, ST_E_INVALID, C_INVPWDLEN, "%SYSTEM-F-INVPWDLEN, password length must be between the minimum and 64 characters");
    for (i = 0; i < MAXUSERS && users[i].used; i++) ;
    if (i == MAXUSERS) return fail(e, ST_E_INTERNAL, 0, "stub SYSUAF full");
    u = &users[i];
    *u = *t;                                   /* the template's record, as AUTHORIZE copies it */
    st_copy(u->u.username, sizeof u->u.username, n->username);
    u->u.uic = n->uic;
    u->u.last_login_i = u->u.last_login_n = 0;
    u->u.login_fails = 0;
    st_copy(u->password, sizeof u->password, n->password);
    u->u.pwd_date = n->pre_expired ? -1 : (long long) time(NULL);
    if (n->more.fields && st_plat_user_modify(n->username, &n->more, e)) {
        memset(u, 0, sizeof *u);               /* undo: nothing left behind */
        return -1;
    }
    if (n->copy_identifiers)
        for (i = 0; i < MAXHOLDS; i++)
            if (holds[i].used && holds[i].uic == t->u.uic) hold_raw(holds[i].value, n->uic, holds[i].attrib);
    if (n->create_directory && !u->u.defdev[0])   /* as the VMS platform: never a bare directory */
        st_copy(n->warning, sizeof n->warning, "no directory was created: the account has no default device");
    return 0;
}

int st_plat_user_delete(const char *username, st_err *e)
{
    stub_user *u;
    int i;
    if (!persona) { set_err(e, ST_E_INTERNAL, "no persona"); return -1; }
    if (!(u = find_user(username))) return fail(e, ST_E_NOTFOUND, C_RNF, "%RMS-E-RNF, record not found");
    if (!system_access()) return fail(e, ST_E_NOPRIV, C_RMS_PRV, "%RMS-E-PRV, insufficient privilege or file protection violation");
    for (i = 0; i < MAXHOLDS; i++)               /* its holdings, as AUTHORIZE REMOVE */
        if (holds[i].used && holds[i].uic == u->u.uic) holds[i].used = 0;
    memset(u, 0, sizeof *u);
    return 0;
}

/* ---------------------------------------------------------------- access history (D13) */

/* A day on a small system, relative to now: what each source would give. The files
   behind accounting, the journal, the SSH logs and Steward's log need SYSPRV or
   READALL, as on the node; the live list is the persona's own process scan. */
int st_plat_access(long long since, long long until, st_access_cb fn, void *ctx,
                   unsigned int src_cond[ST_SRC_COUNT], char src_text[ST_SRC_COUNT][96], st_err *e)
{
    static const struct {
        long long ago, dur;      /* seconds before now; duration (0: none, -1: still on) */
        int kind, src;
        const char *user, *route, *from, *term, *detail;
    } ev[] = {
        { 300, -1, ST_AE_CONNECTED, ST_SRC_LIVE, "SYSTEM", "SSH", "198.51.100.20", "FTA12:", "connected now" },
        { 900, -1, ST_AE_CONNECTED, ST_SRC_LIVE, "WEBMASTER", "TELNET", "198.51.100.45", "TNA3:", "connected now" },
        { 1500, 410, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "publickey ED25519" },
        { 2400, 0, ST_AE_FAILURE, ST_SRC_AUDIT, "ROOT", "SSH", "203.0.113.50", "", "%LOGIN-F-NOSUCHUSER, no such user" },
        { 2410, 0, ST_AE_FAILURE, ST_SRC_AUDIT, "ADMIN", "SSH", "203.0.113.50", "", "%LOGIN-F-NOSUCHUSER, no such user" },
        { 2420, 0, ST_AE_BREAKIN, ST_SRC_AUDIT, "SYSTEM", "SSH", "203.0.113.50", "", "break-in evasion: 203.0.113.50" },
        { 3600, 95, ST_AE_SESSION, ST_SRC_STEWARD, "STEWARD_ADM", "Steward", "198.51.100.20", "", "signed in" },
        { 5400, 0, ST_AE_FAILURE, ST_SRC_STEWARD, "STEWARD_TEST", "Steward", "198.51.100.31", "", "%LOGIN-F-INVPWD, invalid password" },
        /* a script connecting every few seconds: shown as one run */
        { 6000, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 6004, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 6011, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 6015, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 6060, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 6090, 2, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_ADM", "SSH", "198.51.100.20", "", "command, publickey ED25519; host ops-laptop" },
        { 7200, 61, ST_AE_SESSION, ST_SRC_ACCOUNTING, "SYSTEM", "batch", "", "", "queue SYS$BATCH, job BACKUP_NIGHTLY" },
        { 10800, 1834, ST_AE_SESSION, ST_SRC_ACCOUNTING, "WEBMASTER", "SSH", "198.51.100.45", "", "password, SFTP" },
        { 14400, 5120, ST_AE_SESSION, ST_SRC_ACCOUNTING, "SYSTEM", "local", "", "OPA0:", "console" },
        { 43200, 900, ST_AE_SESSION, ST_SRC_ACCOUNTING, "STEWARD_TEST", "TELNET", "198.51.100.46", "TNA1:", "" },
    };
    long long now = (long long) time(NULL);
    int allowed = may_read_uaf(), i;
    (void) e;
    for (i = 0; i < ST_SRC_COUNT; i++) {
        src_cond[i] = 0;
        src_text[i][0] = '\0';
        if (i != ST_SRC_LIVE && !allowed) {
            src_cond[i] = C_RMS_PRV;
            st_copy(src_text[i], 96, "%RMS-E-PRV, insufficient privilege or file protection violation");
        }
    }
    for (i = 0; i < (int) (sizeof ev / sizeof ev[0]); i++) {
        st_access_event a;
        if (src_cond[ev[i].src]) continue;
        /* $GETJPI as the persona: without WORLD, only one's own processes */
        if (ev[i].src == ST_SRC_LIVE && !cur_has(16) && (!persona || strcmp(persona->u.username, ev[i].user))) continue;
        memset(&a, 0, sizeof a);
        a.start = now - ev[i].ago;
        a.end = ev[i].dur > 0 ? a.start + ev[i].dur : 0;
        if ((a.end ? a.end : a.start) < since || a.start > until) continue;
        a.kind = ev[i].kind;
        a.source = ev[i].src;
        st_copy(a.user, sizeof a.user, ev[i].user);
        st_copy(a.route, sizeof a.route, ev[i].route);
        st_copy(a.from, sizeof a.from, ev[i].from);
        st_copy(a.terminal, sizeof a.terminal, ev[i].term);
        st_copy(a.detail, sizeof a.detail, ev[i].detail);
        a.pid = 0x7000u + (unsigned) i;
        if (fn(&a, ctx)) break;
    }
    return 0;
}

/* ---------------------------------------------------------------- logical names (D14) */

/* A few tables as SHOW LOGICAL/FULL prints them, so the parser in st_lnm.c is the one
   that reads them, as on OpenVMS. Each entry is one name: its line, and its further
   equivalences on lines of their own. */
typedef struct { const char *table, *header, *protection; const char *const *names; } stub_table;

static const char *const sys_names[] = {
    "  \"DCL$PATH\" [super] = \"SYS$SYSTEM:\"\n\t= \"SYS$LIBRARY:\"",
    "  \"MOTD\" [exec] = \"Welcome to \"\"X86VMS\"\"\"",
    "  \"STEWARD$ROOT\" [exec] = \"X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.]\" [concealed,terminal]",
    "  \"SYS$COMMON\" [exec] = \"X86VMS$DKA0:[SYS0.SYSCOMMON.]\" [concealed,terminal]",
    "  \"SYS$MANAGER\" [exec] = \"SYS$SYSROOT:[SYSMGR]\"",
    "  \"SYS$SYSDEVICE\" [exec] = \"X86VMS$DKA0:\" [concealed,terminal]",
    "  \"SYS$SYSROOT\" [exec] = \"X86VMS$DKA0:[SYS0.]\" [concealed,terminal]\n\t= \"SYS$COMMON:\"",
    "  \"SYS$SYSTEM\" [exec] = \"SYS$SYSROOT:[SYSEXE]\"",
    "  \"TCPIP$INET_HOST\" [exec] = \"x86vms\"",
    NULL };
static const char *const cluster_names[] = { NULL };
static const char *const g362_names[] = {
    "  \"PROJECT_DATA\" [super] = \"DKA100:[PROJECTS.STEWARD]\"",
    "  \"PROJECT_LOG\" [super] = \"PROJECT_DATA:[LOG]\"",
    NULL };
static const char *const g1_names[] = { "  \"SYSTEM_TOOLS\" [exec] = \"SYS$SYSDEVICE:[TOOLS]\"", NULL };
static const char *const dir_names[] = {
    "  \"LNM$CLUSTER\" [kernel,no_alias] = \"LNM$CLUSTER_TABLE\" [terminal]",
    "  \"LNM$FILE_DEV\" [super] = \"LNM$PROCESS\"\n\t= \"LNM$JOB\"\n\t= \"LNM$GROUP\"\n\t= \"LNM$SYSTEM\"",
    "  \"LNM$GROUP_000001\" [kernel,no_alias,table] = \"\" [terminal]",
    "  \"LNM$GROUP_000362\" [kernel,no_alias,table] = \"\" [terminal]",
    "  \"LNM$JOB_8210AE00\" [kernel,no_alias,table] = \"\" [terminal]",
    "  \"LNM$SYSCLUSTER_TABLE\" [kernel,no_alias,table,clusterwide] = \"\" [terminal]",
    "  \"LNM$SYSTEM\" [kernel,no_alias] = \"LNM$SYSTEM_TABLE\" [terminal]",
    "  \"LNM$SYSTEM_TABLE\" [kernel,no_alias,table] = \"\" [terminal]",
    NULL };
static const char *const job_names[] = { "  \"SYS$LOGIN\" [exec] = \"SYS$SYSDEVICE:[SYSMGR]\"", NULL };

static const stub_table stub_tables[] = {
    { "LNM$SYSTEM_TABLE", "[kernel]  [shareable,system]", "(RWC,RWC,R,R)]  [Owner=[SYSTEM]", sys_names },
    { "LNM$SYSCLUSTER_TABLE", "[kernel]  [shareable,clusterwide]", "(RWC,RWC,R,R)]  [Owner=[SYSTEM]", cluster_names },
    { "LNM$SYSTEM_DIRECTORY", "[kernel]  [shareable,directory]", "(RWC,RWC,R,R)]  [Owner=[SYSTEM]", dir_names },
    { "LNM$GROUP_000362", "[kernel]  [shareable,group]", "(RWCD,R,R,)]  [Owner=[362,*]", g362_names },
    { "LNM$GROUP_000001", "[kernel]  [shareable,group]", "(RWCD,R,R,)]  [Owner=[1,*]", g1_names },
    { "LNM$JOB_8210AE00", "[kernel]  [shareable]", "(RWCD,RWCD,,)]  [Owner=[SYSTEM]", job_names },
};

/* As OpenVMS would decide: system-wide tables for anyone; a group table for its group,
   or with SYSPRV; another job's table with SYSPRV only. */
static int stub_may_read(const stub_table *t)
{
    unsigned int group;
    if (!strncmp(t->table, "LNM$GROUP_", 10)) {
        group = (unsigned int) strtoul(t->table + 10, NULL, 8);
        return system_access() || (persona && (persona->u.uic >> 16) == group);
    }
    if (!strncmp(t->table, "LNM$JOB_", 8)) return system_access();
    return 1;
}

/* LNM$GROUP is the viewer's group table; LNM$SYSTEM and LNM$CLUSTER name theirs. */
static const stub_table *stub_find_table(const char *name)
{
    char g[24];
    size_t i;
    if (!strcmp(name, "LNM$GROUP")) {
        snprintf(g, sizeof g, "LNM$GROUP_%06o", persona ? (persona->u.uic >> 16) : 0u);
        name = g;
    } else if (!strcmp(name, "LNM$SYSTEM")) name = "LNM$SYSTEM_TABLE";
    else if (!strcmp(name, "LNM$CLUSTER")) name = "LNM$SYSCLUSTER_TABLE";
    for (i = 0; i < sizeof stub_tables / sizeof stub_tables[0]; i++)
        if (!strcmp(stub_tables[i].table, name)) return &stub_tables[i];
    return NULL;
}

/* The names, changeable (Phase 7b): loaded from the tables above on first use. Each
   is one name at one mode, as SHOW LOGICAL/FULL would print it. */
#define STUB_LNM_MAX 64
typedef struct { int used; const stub_table *table; char name[ST_LNM_NAME_MAX + 1]; int mode; char *text; } stub_lnm;
static stub_lnm stub_lnms[STUB_LNM_MAX];

static int stub_mode_of(const char *line)
{
    static const char *const names[] = { "kernel", "exec", "super", "user" };
    const char *b = strstr(line, "\" [");
    int m;
    if (!b) return 3;
    for (m = 0; m < 4; m++)
        if (!strncmp(b + 3, names[m], strlen(names[m]))) return m;
    return 3;
}

static void stub_lnm_load(void)
{
    static int loaded;
    size_t t;
    int i, k = 0;
    if (loaded) return;
    loaded = 1;
    for (t = 0; t < sizeof stub_tables / sizeof stub_tables[0]; t++)
        for (i = 0; stub_tables[t].names[i] && k < STUB_LNM_MAX; i++, k++) {
            const char *line = stub_tables[t].names[i], *q = strchr(line, '"'), *r = q ? strchr(q + 1, '"') : NULL;
            size_t n = (q && r) ? (size_t) (r - q - 1) : 0;
            if (n > ST_LNM_NAME_MAX) n = ST_LNM_NAME_MAX;
            stub_lnms[k].used = 1;
            stub_lnms[k].table = &stub_tables[t];
            memcpy(stub_lnms[k].name, q ? q + 1 : "", n);
            stub_lnms[k].name[n] = '\0';
            stub_lnms[k].mode = stub_mode_of(line);
            stub_lnms[k].text = (char *) line;   /* never freed: k < the static count */
        }
}

static int stub_lnm_static(int i)
{
    size_t t;
    int j;
    for (t = 0; t < sizeof stub_tables / sizeof stub_tables[0]; t++)
        for (j = 0; stub_tables[t].names[j]; j++)
            if (stub_lnms[i].text == stub_tables[t].names[j]) return 1;
    return 0;
}

static int stub_lnm_outermost(int i)
{
    int j;
    for (j = 0; j < STUB_LNM_MAX; j++)
        if (j != i && stub_lnms[j].used && stub_lnms[j].table == stub_lnms[i].table &&
            !strcmp(stub_lnms[j].name, stub_lnms[i].name) && stub_lnms[j].mode > stub_lnms[i].mode)
            return 0;
    return 1;
}

static void stub_lines(st_lnm_parser *p, const char *text)
{
    while (*text) {
        const char *nl = strchr(text, '\n');
        size_t n = nl ? (size_t) (nl - text) : strlen(text);
        st_lnm_parse_line(p, text, n);
        text += n + (nl ? 1 : 0);
    }
}

int st_plat_lnm_list(const char *table, const char *pattern, const char *privs,
                     st_lnm_cb fn, void *ctx, st_err *e)
{
    const stub_table *t = stub_find_table(table);
    st_lnm_parser p;
    char line[200];
    int i;
    (void) privs;   /* the stub persona already has the session's privileges */
    /* As SHOW LOGICAL answers on the node: a table that does not exist and one the
       viewer may not read are the same, IVLOGTAB (2026-10-11). */
    if (!t || !stub_may_read(t))
        return fail(e, ST_E_NOTFOUND, C_IVLOGTAB, "%SYSTEM-W-IVLOGTAB, invalid logical name table");
    st_lnm_parse_init(&p, fn, ctx);
    snprintf(line, sizeof line, "(%s)\t%s", t->table, t->header);
    st_lnm_parse_line(&p, line, strlen(line));
    snprintf(line, sizeof line, "\t\t\t[Protection=%s]", t->protection);
    st_lnm_parse_line(&p, line, strlen(line));
    stub_lnm_load();
    /* SHOW LOGICAL shows a name once, at its outermost mode. */
    for (i = 0; i < STUB_LNM_MAX; i++)
        if (stub_lnms[i].used && stub_lnms[i].table == t && st_wild_match(pattern, stub_lnms[i].name) &&
            stub_lnm_outermost(i))
            stub_lines(&p, stub_lnms[i].text);
    st_lnm_parse_end(&p);
    return 0;
}

typedef struct { const char *want; st_lnm *out; int found; } stub_get;

static int stub_get_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    stub_get *g = ctx;
    (void) t;
    if (strcmp(n->name, g->want)) return 0;
    *g->out = *n;
    g->found = 1;
    return 1;
}

int st_plat_lnm_get(const char *table, const char *name, int mode, st_lnm *out,
                    char table_out[ST_LNM_TABLE_MAX + 1], st_err *e)
{
    const stub_table *t = stub_find_table(table);
    stub_get g;
    char pattern[ST_LNM_PATTERN_MAX + 1];
    /* Only real tables, by their own names, as on OpenVMS: not LNM$SYSTEM or
       LNM$CLUSTER (search lists, NOLOGTAB there), not the directory. */
    if (!t || strcmp(t->table, table) || !strcmp(t->table, "LNM$SYSTEM_DIRECTORY"))
        return fail(e, ST_E_NOTFOUND, C_NOLOGTAB, "%SYSTEM-F-NOLOGTAB, no logical name table matches the specified name");
    if (!stub_may_read(t)) return fail(e, ST_E_NOPRIV, C_NOPRIV, "%SYSTEM-F-NOPRIV, insufficient privilege or object protection violation");
    g.want = name; g.out = out; g.found = 0;
    if (mode >= 0) {   /* the definition at exactly that mode, through the parser */
        st_lnm_parser p;
        char line[200];
        int i;
        stub_lnm_load();
        st_lnm_parse_init(&p, stub_get_cb, &g);
        snprintf(line, sizeof line, "(%s)\t%s", t->table, t->header);
        st_lnm_parse_line(&p, line, strlen(line));
        for (i = 0; i < STUB_LNM_MAX; i++)
            if (stub_lnms[i].used && stub_lnms[i].table == t && stub_lnms[i].mode == mode &&
                !strcmp(stub_lnms[i].name, name))
                stub_lines(&p, stub_lnms[i].text);
        st_lnm_parse_end(&p);
    } else {
        st_copy(pattern, sizeof pattern, "*");
        if (st_plat_lnm_list(t->table, pattern, "-", stub_get_cb, &g, e)) return -1;
    }
    if (!g.found) { fail(e, ST_E_NOTFOUND, C_NOLOGNAM, "%SYSTEM-F-NOLOGNAM, no logical name match"); return 0; }
    st_copy(table_out, ST_LNM_TABLE_MAX + 1, t->table);
    return 1;
}

/* ---- changes (Phase 7b, D15) ---- */

/* As OpenVMS decides, per probe_crelnm (NOTES.md): the system-wide tables with SYSPRV
   (their protection) or SYSNAM; a group table with GRPPRV for one's own group, GRPNAM,
   or SYSPRV. SYSNAM does not open a group table. */
static int stub_may_write(const stub_table *t)
{
    if (!strncmp(t->table, "LNM$GROUP_", 10)) {
        unsigned int group = (unsigned int) strtoul(t->table + 10, NULL, 8);
        return system_access() ||
               (persona && (persona->u.uic >> 16) == group && (cur_has(P_GRPPRV) || cur_has(P_GRPNAM)));
    }
    return system_access() || cur_has(P_SYSNAM);
}

static const stub_table *stub_real_table(const char *table, st_err *e)
{
    const stub_table *t = stub_find_table(table);
    if (!t || strcmp(t->table, table) || !strcmp(t->table, "LNM$SYSTEM_DIRECTORY")) {
        fail(e, ST_E_NOTFOUND, C_NOLOGTAB, "%SYSTEM-F-NOLOGTAB, no logical name table matches the specified name");
        return NULL;
    }
    return t;
}

static int stub_nosysnam(int mode, st_err *e)
{
    if (mode < ST_LNM_USER && !cur_has(P_SYSNAM))
        return fail(e, ST_E_NOPRIV, C_NOSYSNAM, "%SYSTEM-F-NOSYSNAM, operation requires SYSNAM privilege");
    return 0;
}

static int stub_noprive(st_err *e)
{
    return fail(e, ST_E_NOPRIV, C_NOPRIV, "%SYSTEM-F-NOPRIV, insufficient privilege or object protection violation");
}

int st_plat_lnm_modes(const char *table, const char *name, st_err *e)
{
    const stub_table *t = stub_real_table(table, e);
    int i, bits = 0;
    if (!t) return -1;
    if (!stub_may_read(t)) return stub_noprive(e);
    stub_lnm_load();
    for (i = 0; i < STUB_LNM_MAX; i++)
        if (stub_lnms[i].used && stub_lnms[i].table == t && !strcmp(stub_lnms[i].name, name))
            bits |= 1 << stub_lnms[i].mode;
    return bits;
}

/* "x" with quotes doubled, as SHOW LOGICAL prints a string. */
static void stub_quoted(st_buf *b, const char *s)
{
    st_buf_putc(b, '"');
    for (; *s; s++) {
        if (*s == '"') st_buf_putc(b, '"');
        st_buf_putc(b, *s);
    }
    st_buf_putc(b, '"');
}

int st_plat_lnm_define(const st_lnm_def *d, st_err *e)
{
    const stub_table *t = stub_real_table(d->table, e);
    st_buf b;
    char *text;
    int i, slot = -1, replaced = 0;
    if (!t) return -1;
    if (stub_nosysnam(d->mode, e)) return -1;
    if (!stub_may_write(t)) return stub_noprive(e);
    stub_lnm_load();
    st_buf_init(&b, 0);
    st_buf_puts(&b, "  ");
    stub_quoted(&b, d->name);
    st_buf_printf(&b, " [%s%s%s]", st_lnm_mode_name(d->mode), (d->attrs & ST_LNM_NO_ALIAS) ? ",no_alias" : "",
                (d->attrs & ST_LNM_CONFINE) ? ",confine" : "");
    for (i = 0; i < d->neq; i++) {
        unsigned a = d->eq[i].attrs;
        st_buf_puts(&b, i ? "\n\t= " : " = ");
        stub_quoted(&b, d->eq[i].value);
        if (a) st_buf_printf(&b, " [%s%s%s]", (a & ST_LNM_CONCEALED) ? "concealed" : "",
                           (a & ST_LNM_CONCEALED) && (a & ST_LNM_TERMINAL) ? "," : "",
                           (a & ST_LNM_TERMINAL) ? "terminal" : "");
    }
    text = st_buf_ok(&b) ? malloc(b.len + 1) : NULL;
    if (!text) { st_buf_free(&b); set_err(e, ST_E_INTERNAL, "out of memory"); return -1; }
    memcpy(text, st_buf_cstr(&b), b.len + 1);
    st_buf_free(&b);
    for (i = 0; i < STUB_LNM_MAX; i++)
        if (stub_lnms[i].used && stub_lnms[i].table == t && stub_lnms[i].mode == d->mode &&
            !strcmp(stub_lnms[i].name, d->name)) { slot = i; replaced = 1; break; }
    for (i = 0; slot < 0 && i < STUB_LNM_MAX; i++)
        if (!stub_lnms[i].used) slot = i;
    if (slot < 0) { free(text); set_err(e, ST_E_INTERNAL, "stub: too many logical names"); return -1; }
    if (replaced && !stub_lnm_static(slot)) free(stub_lnms[slot].text);
    /* NO_ALIAS: OpenVMS deletes the name at every outer mode (NOTES.md). */
    if (d->attrs & ST_LNM_NO_ALIAS)
        for (i = 0; i < STUB_LNM_MAX; i++)
            if (i != slot && stub_lnms[i].used && stub_lnms[i].table == t && stub_lnms[i].mode > d->mode &&
                !strcmp(stub_lnms[i].name, d->name)) {
                if (!stub_lnm_static(i)) free(stub_lnms[i].text);
                stub_lnms[i].used = 0;
            }
    stub_lnms[slot].used = 1;
    stub_lnms[slot].table = t;
    st_copy(stub_lnms[slot].name, sizeof stub_lnms[slot].name, d->name);
    stub_lnms[slot].mode = d->mode;
    stub_lnms[slot].text = text;
    return replaced ? 2 : 1;
}

int st_plat_lnm_deassign(const char *table, const char *name, int mode, st_err *e)
{
    const stub_table *t = stub_real_table(table, e);
    int i, n = 0;
    if (!t) return -1;
    if (stub_nosysnam(mode, e)) return -1;
    if (!stub_may_write(t)) return stub_noprive(e);
    stub_lnm_load();
    for (i = 0; i < STUB_LNM_MAX; i++)
        if (stub_lnms[i].used && stub_lnms[i].table == t && stub_lnms[i].mode >= mode &&
            !strcmp(stub_lnms[i].name, name)) {
            if (!stub_lnm_static(i)) free(stub_lnms[i].text);
            stub_lnms[i].used = 0;
            n++;
        }
    if (!n) { fail(e, ST_E_NOTFOUND, C_NOLOGNAM, "%SYSTEM-F-NOLOGNAM, no logical name match"); return -1; }
    return 0;
}

/* ---------------------------------------------------------------- processes (D16) */

/* A few processes as x86 has them (PHASE8.md): system ones, Steward's pool in
   [362,10] (the service account shares group 362 with the test accounts there), a
   pool worker busy with STEWARD_TEST's request (reported as STEWARD_TEST [362,1],
   but seen and stopped as its real owner, the pool: NOTES.md), STEWARD_TEST's
   session, and another group's. The process serving the request is not among them,
   as on OpenVMS it is never given. */
typedef struct {
    unsigned int pid; const char *name, *user; unsigned int uic; int state, pri, prib, mode, sub;
    const char *term, *image; unsigned int cpu, dirio, bufio, pf; int age;
    unsigned int owner_uic;   /* who may see and stop it, if not uic (a persona held) */
} stub_proc;

static const stub_proc stub_procs[] = {
    { 0x00000401, "SWAPPER", "SYSTEM", 0x00010004u, 7, 16, 0, 0, 0, "", "", 12, 0, 0, 0, 86400, 0 },
    { 0x0000040B, "OPCOM", "SYSTEM", 0x00010004u, 7, 8, 6, 0, 0, "", "X86VMS$DKA0:[SYS0.SYSCOMMON.][SYSEXE]OPCOM.EXE", 140, 30, 900, 410, 86400, 0 },
    { 0x00007500, "STEWARD_19300", "STEWARD", 0x00F20008u, 5, 4, 4, 0, 0, "", "X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]STEWARD.EXE;1", 1600, 220, 5100, 3100, 3600, 0 },
    { 0x00007501, "STEWARD_19301", "STEWARD", 0x00F20008u, 5, 4, 4, 0, 0, "", "X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]STEWARD.EXE;1", 1200, 180, 4300, 2900, 3600, 0 },
    { 0x00007502, "STEWARD_19302", "STEWARD_TEST", 0x00F20001u, 14, 4, 4, 0, 0, "", "X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]STEWARD.EXE;1", 900, 90, 2100, 1700, 3600, 0x00F20008u },
    { 0x00007520, "STEWARD_TEST", "STEWARD_TEST", 0x00F20001u, 5, 4, 4, 3, 0, "FTA12:", "", 35, 120, 300, 800, 1200, 0 },
    { 0x00007521, "_FTA12:_S1", "STEWARD_TEST", 0x00F20001u, 7, 4, 4, 3, 1, "", "X86VMS$DKA0:[SYS0.SYSCOMMON.][SYSEXE]MONITOR.EXE;1", 9, 4, 40, 200, 600, 0 },
    { 0x00007530, "WEBMASTER", "WEBMASTER", 0x00C80021u, 5, 4, 4, 3, 0, "FTA14:", "", 70, 60, 500, 900, 2400, 0 },
};

static int stub_stopped[sizeof stub_procs / sizeof stub_procs[0]];

/* As OpenVMS decides (probe_jpi, probe_delprc): one's own UIC, one's group with GROUP,
   any with WORLD; the same for seeing and for stopping. */
static int stub_may_see(const stub_proc *p)
{
    unsigned int owner = p->owner_uic ? p->owner_uic : p->uic;
    if (!persona || stub_stopped[p - stub_procs]) return 0;
    if (owner == persona->u.uic || cur_has(P_WORLD)) return 1;
    return cur_has(P_GROUP) && (owner >> 16) == (persona->u.uic >> 16);
}

static void stub_proc_fill(const stub_proc *s, st_proc *p)
{
    memset(p, 0, sizeof *p);
    p->pid = s->pid;
    st_copy(p->name, sizeof p->name, s->name);
    st_copy(p->username, sizeof p->username, s->user);
    p->uic = s->uic;
    p->state = s->state;
    p->pri = s->pri;
    p->prib = s->prib;
    p->mode = s->mode;
    p->subprocess = s->sub;
    st_copy(p->terminal, sizeof p->terminal, s->term);
    st_copy(p->image, sizeof p->image, s->image);
    p->cputim = s->cpu;
    p->dirio = s->dirio;
    p->bufio = s->bufio;
    p->pageflts = s->pf;
    p->login = (long long) time(NULL) - s->age;
}

int st_plat_proc_enum(st_proc_cb fn, void *ctx, st_err *e)
{
    size_t i;
    st_proc p;
    (void) e;
    for (i = 0; i < sizeof stub_procs / sizeof stub_procs[0]; i++) {
        if (!stub_may_see(&stub_procs[i])) continue;
        stub_proc_fill(&stub_procs[i], &p);
        if (fn(&p, ctx)) break;
    }
    return 0;
}

int st_plat_proc_get(unsigned int pid, st_proc_detail *d, st_err *e)
{
    size_t i;
    memset(d, 0, sizeof *d);
    for (i = 0; i < sizeof stub_procs / sizeof stub_procs[0]; i++) {
        const stub_proc *s = &stub_procs[i];
        if (s->pid != pid || stub_stopped[i]) continue;
        if (!stub_may_see(s)) return stub_noprive(e);
        stub_proc_fill(s, &d->p);
        if (s->sub) d->owner = s->pid - 1;
        d->master = s->sub ? s->pid - 1 : s->pid;
        d->wssize = 4096;
        d->wspages = 1800;
        d->priv_cur[0] = d->priv_auth[0] = (1u << 15) | (1u << 20);   /* TMPMBX, NETMBX */
        if (s->uic == 0x00010004u) d->priv_cur[0] = d->priv_auth[0] = 0xFFFFFFFFu;
        d->nids = 0;
        if (s->uic >> 16 == 0xF2) st_copy(d->ids[d->nids++], sizeof d->ids[0], "STEWARD_OPS");
        {
            static const unsigned int q[ST_PQ_COUNT] = { 300, 150, 150, 128, 8, 100, 4000, 128000, 256000 };
            int k;
            for (k = 0; k < ST_PQ_COUNT; k++) { d->quota[k] = q[k]; d->left[k] = q[k] - q[k] / 10; }
        }
        return 0;
    }
    return fail(e, ST_E_NOTFOUND, C_NONEXPR, "%SYSTEM-W-NONEXPR, nonexistent process");
}

int st_plat_proc_stop(unsigned int pid, st_err *e)
{
    size_t i;
    for (i = 0; i < sizeof stub_procs / sizeof stub_procs[0]; i++) {
        if (stub_procs[i].pid != pid || stub_stopped[i]) continue;
        if (!stub_may_see(&stub_procs[i])) return stub_noprive(e);
        stub_stopped[i] = 1;
        return 0;
    }
    return fail(e, ST_E_NOTFOUND, C_NONEXPR, "%SYSTEM-W-NONEXPR, nonexistent process");
}

/* ---------------------------------------------------------------- queues (D17) */

/* As x86 has them (PHASE9.md): SYS$BATCH generic, feeding X86VMS_BATCH; two print
   queues, one stopped. Jobs: STEWARD_TEST's held, the work account's executing, and
   STEWARD_ADM's pending. */
typedef struct { const char *name; int batch, generic; unsigned int status; const char *node, *desc; unsigned int limit; } stub_queue;
static const stub_queue stub_queues[] = {
    { "SYS$BATCH", 1, 1, 0x0, "", "Batch: generic", 0 },
    { "X86VMS_BATCH", 1, 0, 0x40000 | 0x10000, "X86VMS", "Batch on X86VMS", 4 },
    { "SYS$PRINT", 0, 1, 0x0, "", "", 0 },
    { "LPA0_PRINT", 0, 0, 0x1000, "X86VMS", "Line printer (stopped)", 1 },
};
typedef struct { unsigned int entry; const char *name, *user; unsigned int uic, status; const char *queue, *file; int age; } stub_job;
static const stub_job stub_jobs[] = {
    { 269, "NIGHTLY", "STEWARD_TEST", 0x00F20001u, 0x4, "SYS$BATCH", "SYS$SYSDEVICE:[STEWARD_TEST]NIGHTLY.COM;1", 600 },
    { 141, "BZSOAK", "IAIN", 0x00C80065u, 0x2, "X86VMS_BATCH", "X86VMS$DKA300:[IAIN]BZSOAK.COM;3", 86400 },
    { 272, "REPORT", "STEWARD_ADM", 0x00F20002u, 0x800, "X86VMS_BATCH", "SYS$SYSDEVICE:[STEWARD_ADM]REPORT.COM;1", 60 },
};

/* As the queue manager decides (probe_qui): one's own and one's group's jobs (the
   queues give G:R), anyone's with SYSPRV; the rest inaccessible. */
static int stub_may_read_job(const stub_job *j)
{
    if (!persona) return 0;
    return system_access() || (j->uic >> 16) == (persona->u.uic >> 16);
}

static void stub_job_fill(const stub_job *s, st_job *j)
{
    memset(j, 0, sizeof *j);
    j->entry = s->entry;
    st_copy(j->queue, sizeof j->queue, s->queue);
    if (!stub_may_read_job(s)) { j->status = s->status | ST_JOB_INACCESSIBLE; return; }
    j->status = s->status;
    st_copy(j->name, sizeof j->name, s->name);
    st_copy(j->username, sizeof j->username, s->user);
    j->submitted = (long long) time(NULL) - s->age;
}

static void stub_queue_fill(const stub_queue *s, st_queue *q)
{
    size_t i;
    memset(q, 0, sizeof *q);
    st_copy(q->name, sizeof q->name, s->name);
    q->batch = s->batch;
    q->generic = s->generic;
    q->status = s->status;
    st_copy(q->node, sizeof q->node, s->node);
    st_copy(q->description, sizeof q->description, s->desc);
    q->job_limit = s->limit;
    for (i = 0; i < sizeof stub_jobs / sizeof stub_jobs[0]; i++)
        if (!strcmp(stub_jobs[i].queue, s->name)) {
            unsigned int st = stub_jobs[i].status;
            if (st & 0x2) q->executing++;
            if (st & 0x800) q->pending++;
            if (st & 0x4) q->holding++;
            if (st & 0x200) q->timed++;
        }
}

int st_plat_queue_enum(st_queue_cb fn, void *ctx, st_err *e)
{
    size_t i;
    st_queue q;
    (void) e;
    for (i = 0; i < sizeof stub_queues / sizeof stub_queues[0]; i++) {
        stub_queue_fill(&stub_queues[i], &q);
        if (fn(&q, ctx)) break;
    }
    return 0;
}

int st_plat_queue_get(const char *name, st_queue *q, st_job_cb fn, void *ctx, st_err *e)
{
    size_t i;
    st_job j;
    for (i = 0; i < sizeof stub_queues / sizeof stub_queues[0]; i++)
        if (!strcmp(stub_queues[i].name, name)) break;
    if (i == sizeof stub_queues / sizeof stub_queues[0])
        return fail(e, ST_E_NOTFOUND, C_NOSUCHQUE, "%JBC-E-NOSUCHQUE, no such queue");
    stub_queue_fill(&stub_queues[i], q);
    for (i = 0; i < sizeof stub_jobs / sizeof stub_jobs[0]; i++) {
        if (strcmp(stub_jobs[i].queue, name)) continue;
        stub_job_fill(&stub_jobs[i], &j);
        if (fn(&j, ctx)) break;
    }
    return 0;
}

int st_plat_job_get(unsigned int entry, st_job_detail *d, st_err *e)
{
    size_t i;
    memset(d, 0, sizeof *d);
    for (i = 0; i < sizeof stub_jobs / sizeof stub_jobs[0]; i++) {
        const stub_job *s = &stub_jobs[i];
        if (s->entry != entry) continue;
        if (!stub_may_read_job(s)) return stub_noprive(e);
        stub_job_fill(s, &d->j);
        d->priority = 100;
        d->uic = s->uic;
        st_copy(d->account, sizeof d->account, "STEWARD");
        snprintf(d->log, sizeof d->log, "SYS$SYSDEVICE:[%s]%s.LOG", s->user, s->name);
        st_copy(d->files[d->nfiles++], sizeof d->files[0], s->file);
        return 0;
    }
    return fail(e, ST_E_NOTFOUND, C_NOSUCHENT, "%JBC-E-NOSUCHENT, no such entry");
}

/* ================================================================ misc */

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
