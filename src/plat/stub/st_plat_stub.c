/* st_plat_stub.c - in-memory platform for Linux tests and front-end work.

   A handful of fixed accounts stand in for SYSUAF, behaving as the x86 probes showed
   the real thing does (docs/PHASE0.md, docs/PHASE1.md):

     STEWARD_ADM    admin-pass     [362,2] defaults TMPMBX, NETMBX, OPER; SYSPRV and
                                   GRPPRV authorized only (the habit D9 respects);
                                   holds STEWARD_DEMO
     STEWARD_TEST   test-pass      [362,1] TMPMBX, NETMBX only, as on the x86 node
     DISABLED       disabled-pass  DISUSER: fails, reason "account is disabled"
     EXPIRED        expired-pass   right password, but expired

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
      0, 0, { "STEWARD_DEMO", NULL } },
    { "STEWARD_TEST", "test-pass", "Steward test (stub)", "STEWARD", 0x00F20001u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 0, 0, { NULL } },
    { "DISABLED", "disabled-pass", "Disabled account (stub)", "", 0x00F20003u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 1, 0, { NULL } },
    { "EXPIRED", "expired-pass", "Expired password (stub)", "", 0x00F20004u,
      { BIT(15) | BIT(20), 0 }, { BIT(15) | BIT(20), 0 }, 0, 1, { NULL } },
};
#define NUSERS (sizeof users / sizeof users[0])

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
    if (!u || strcmp(u->password, password)) {
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
