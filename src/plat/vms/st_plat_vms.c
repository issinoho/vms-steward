/* st_plat_vms.c - the platform on OpenVMS: system services, RMS, $ACM, personas.

   VSI C, 32-bit pointers (D3). Every finding this file relies on is in
   docs/PHASE0.md or docs/PHASE1.md, with the probe that established it:

   - $ACM, non-dialogue, authenticates; intrusion records name the client when
     ACME$_REMOTE_HOST_NAME and ACME$_REMOTE_USERNAME are given (probe_acm_host).
   - It accepts an expired password (probe_acm), so expiry is checked here, as the
     user: an unprivileged persona may $GETUAI its own record (probe_selfuai).
   - $PERSONA_CREATE reads the user's UAF record, so the service holds SYSPRV as
     authorized and enables it only around that call (D2 amendment, PHASE1.md).
   - Under a persona the OS checks the persona's rights and privileges, and $SETPRV
     is limited by the persona's authorized mask (probe_persona, probe_setprv).
   - Privilege masks above bit 31 are 64-bit; they are carried as two longwords.

   The session and audit files are opened once at start-up, as the service account.
   Access is checked at open, so later writes made while a request's persona is
   assumed still go through the service account's channel. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <descrip.h>
#include <jpidef.h>
#include <dcdef.h>
#include <dvidef.h>
#include <dvsdef.h>
#include <jbcmsgdef.h>
#include <quidef.h>
#include <rmidef.h>
#include <syidef.h>
#include <kgbdef.h>
#include <lnmdef.h>
#include <iodef.h>
#include <prcdef.h>
#include <prvdef.h>
#include <rms.h>
#include <rmsdef.h>
#include <ssdef.h>
#include <starlet.h>
#include <uaidef.h>
#include <uafdef.h>         /* SYS$LIB_C.TLB: the SYSUAF record (D6) */
#include <acrdef.h>         /* accounting records (Phase 6) */
#include <nsadef.h>         /* security audit journal records (Phase 6) */
#include <lib$routines.h>
#include <utcblkdef.h>   /* acmedef.h uses utcblk without including it (PHASE0) */
#include <acmedef.h>
#include "st_platform.h"
#include "st_buf.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

/* Item lists built by hand: the layout of ILE3 with 32-bit pointers. (Not named
   st_ile3: <iledef.h>, pulled in by starlet, already declares that.) */
typedef struct { unsigned short buflen, code; void *buf; unsigned short *retlen; } st_ile3;

static void item(st_ile3 *it, unsigned short code, void *buf, unsigned short len,
                 unsigned short *retlen)
{
    it->buflen = len; it->code = code; it->buf = buf; it->retlen = retlen;
}

static void item_end(st_ile3 *it) { memset(it, 0, sizeof *it); }

static void desc(struct dsc$descriptor_s *d, const char *s, unsigned short len)
{
    d->dsc$w_length = len;
    d->dsc$b_dtype = DSC$K_DTYPE_T;
    d->dsc$b_class = DSC$K_CLASS_S;
    d->dsc$a_pointer = (char *) s;
}

static void blank_trim(const char *buf, size_t len, char *out, size_t outlen);

/* Buffers that a system service or RMS fills are zero-initialised anyway: cppcheck
   cannot see through descriptors and RABs (D8), and an unfilled buffer then reads
   as empty rather than as stack garbage. */
static void msgtext(unsigned int cond, char *out, size_t outlen)
{
    char buf[257] = { 0 };
    unsigned short len = 0;
    struct dsc$descriptor_s d;
    desc(&d, buf, sizeof buf - 1);
    if (!(sys$getmsg(cond, &len, &d, 15, 0) & 1)) { snprintf(buf, sizeof buf, "%%X%08X", cond); len = (unsigned short) strlen(buf); }
    buf[len] = '\0';
    strncpy(out, buf, outlen - 1);
    out[outlen - 1] = '\0';
}

/* Map a condition to what the HTTP layer needs. */
static void set_cond(st_err *e, unsigned int cond)
{
    if (!e) return;
    e->cond = cond;
    msgtext(cond, e->text, sizeof e->text);
    switch (cond) {
    case SS$_NOPRIV: case SS$_NOSYSPRV: case SS$_NOGRPPRV: case RMS$_PRV:
        e->kind = ST_E_NOPRIV; break;
    case SS$_NOSUCHID: case RMS$_RNF: case SS$_NOLOGNAM: case SS$_NOLOGTAB: case SS$_IVLOGTAB:
        e->kind = ST_E_NOTFOUND; break;
    case SS$_IVIDENT: case SS$_BADPARAM: case SS$_INVPWDLEN: case SS$_PWDINHIS:
    case SS$_PWDINDIC: case SS$_PWDWEAK: case SS$_PWDSYNTAX:
        e->kind = ST_E_INVALID; break;
    case SS$_DUPIDENT: case RMS$_DUP:
        e->kind = ST_E_CONFLICT; break;
    default:
        e->kind = (cond == 0 || (cond & 1)) ? ST_OK : ST_E_INTERNAL;
    }
    /* SS$_NOSUCHUSER is defined from V7.2 on; compare without depending on it. */
#ifdef SS$_NOSUCHUSER
    if (cond == SS$_NOSUCHUSER) e->kind = ST_E_NOTFOUND;
#endif
}

static void set_text(st_err *e, int kind, const char *text)
{
    if (!e) return;
    e->kind = kind;
    e->cond = 0;
    strncpy(e->text, text, sizeof e->text - 1);
    e->text[sizeof e->text - 1] = '\0';
}

/* ================================================================ files */

/* Session records: fixed length, explicit offsets, integers little-endian. Never a
   struct written to disk: packing is compiler-specific (CLAUDE.md). */
#define SR_KEY      0     /* 32 bytes, primary key */
#define SR_USER     32    /* 12, blank-padded */
#define SR_CREATED  44    /* 8 */
#define SR_SEEN     52    /* 8 */
#define SR_CSRF     60    /* 32 */
#define SR_CLIENT   92    /* 46, NUL-padded */
#define SR_ENABLE   138   /* 8: privileges switched on (D9), two longwords */
#define SR_LEN      146

static struct FAB   sfab;
static struct RAB   srab;
static struct XABKEY sxab;
static int          session_open;
static struct FAB   afab;
static struct RAB   arab;
static int          audit_open;

static void put64(unsigned char *p, long long v)
{
    int i;
    unsigned long long u = (unsigned long long) v;
    for (i = 0; i < 8; i++) { p[i] = (unsigned char) (u & 0xFF); u >>= 8; }
}

static long long get64(const unsigned char *p)
{
    int i;
    unsigned long long u = 0;
    for (i = 7; i >= 0; i--) u = (u << 8) | p[i];
    return (long long) u;
}

static void encode(const st_session *s, unsigned char *r)
{
    size_t n = strlen(s->username);
    memset(r, 0, SR_LEN);
    memcpy(r + SR_KEY, s->key, 32);
    memset(r + SR_USER, ' ', 12);
    memcpy(r + SR_USER, s->username, n > 12 ? 12 : n);
    put64(r + SR_CREATED, s->created);
    put64(r + SR_SEEN, s->last_seen);
    memcpy(r + SR_CSRF, s->csrf, 32);
    n = strlen(s->client);
    memcpy(r + SR_CLIENT, s->client, n > 45 ? 45 : n);
    put64(r + SR_ENABLE, (long long) (((unsigned long long) s->priv_enable[1] << 32) | s->priv_enable[0]));
}

static void decode(const unsigned char *r, st_session *s)
{
    int n;
    memset(s, 0, sizeof *s);
    memcpy(s->key, r + SR_KEY, 32);
    memcpy(s->username, r + SR_USER, 12);
    for (n = 12; n > 0 && s->username[n - 1] == ' '; n--) s->username[n - 1] = '\0';
    s->created = get64(r + SR_CREATED);
    s->last_seen = get64(r + SR_SEEN);
    memcpy(s->csrf, r + SR_CSRF, 32);
    memcpy(s->client, r + SR_CLIENT, 45);
    {
        unsigned long long m = (unsigned long long) get64(r + SR_ENABLE);
        s->priv_enable[0] = (unsigned int) m;
        s->priv_enable[1] = (unsigned int) (m >> 32);
    }
}

static unsigned int open_sessions(const char *path)
{
    unsigned int st;
    sfab = cc$rms_fab;
    sxab = cc$rms_xabkey;
    sxab.xab$b_dtp = XAB$C_STG;
    sxab.xab$w_pos0 = SR_KEY;
    sxab.xab$b_siz0 = 32;
    sxab.xab$b_ref = 0;
    sfab.fab$l_xab = (void *) &sxab;
    sfab.fab$l_fna = (char *) path;
    sfab.fab$b_fns = (unsigned char) strlen(path);
    sfab.fab$b_org = FAB$C_IDX;
    sfab.fab$b_rfm = FAB$C_FIX;
    sfab.fab$w_mrs = SR_LEN;
    sfab.fab$b_fac = FAB$M_GET | FAB$M_PUT | FAB$M_UPD | FAB$M_DEL;
    sfab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;
    sfab.fab$l_fop = FAB$M_CIF;   /* create if absent, else open: the pool shares one file */
    st = sys$create(&sfab);
    if (!(st & 1)) return st;
    if (sfab.fab$w_mrs != SR_LEN) {
        /* An existing store from an older version, with shorter records. Sessions
           are disposable: stop the pool and delete the file (STEWARD_POOL.COM). */
        st_plat_log("the session store has an older record format; stop the pool and delete it");
        sys$close(&sfab);
        return RMS$_RSZ;
    }
    srab = cc$rms_rab;
    srab.rab$l_fab = &sfab;
    st = sys$connect(&srab);
    if (!(st & 1)) { sys$close(&sfab); return st; }
    session_open = 1;
    return SS$_NORMAL;
}

/* SYSPRV, which $PERSONA_CREATE needs to read the user's UAF record (GRPPRV within
   the service's own UIC group, SYSPRV for everyone else: PHASE1.md). The account
   holds it as authorized, not default, and it is on only around that one call (D2). */
static unsigned int sysprv[2] = { PRV$M_SYSPRV, 0 };

static char service_account[13];
static char steward_log[256];
static char lnm_helper[256] = "STEWARD$ROOT:[COM]STEWARD_LNM.COM";   /* D14 */      /* Steward's audit log, read back for access history */

const char *st_plat_service_account(void) { return service_account; }

int st_plat_init(const st_plat_config *cfg, st_err *e)
{
    unsigned int imp[2] = { PRV$M_DETACH, 0 }, st;   /* IMPERSONATE is the DETACH bit */

    /* The service account is authorized IMPERSONATE; make sure it is enabled. */
    st = sys$setprv(1, (void *) imp, 0, 0);
    if (st != SS$_NORMAL) { set_cond(e, st == SS$_NOTALLPRIV ? SS$_NOPRIV : st); return -1; }
    {   /* who the service is, before any persona: Steward never deletes itself */
        char u[13] = { 0 };
        unsigned short ul = 0;
        unsigned int iosb[2];
        st_ile3 it[2];
        item(&it[0], JPI$_USERNAME, u, 12, &ul);
        item_end(&it[1]);
        if (sys$getjpiw(0, 0, 0, it, iosb, 0, 0) & 1) blank_trim(u, ul, service_account, sizeof service_account);
    }
    /* And SYSPRV off, whatever the account's defaults say. */
    sys$setprv(0, (void *) sysprv, 0, 0);
    if (!st_plat_privileges_clean()) {
        set_text(e, ST_E_INTERNAL, "cannot disable SYSPRV");
        return -1;
    }

    if (!cfg->session_file || !*cfg->session_file) {
        set_text(e, ST_E_INTERNAL, "STEWARD_SESSION_FILE is not defined");
        return -1;
    }
    if (cfg->audit_file) st_copy(steward_log, sizeof steward_log, cfg->audit_file);
    if (getenv("STEWARD_LNM_HELPER") && *getenv("STEWARD_LNM_HELPER")) st_copy(lnm_helper, sizeof lnm_helper, getenv("STEWARD_LNM_HELPER"));
    st = open_sessions(cfg->session_file);
    if (!(st & 1)) { set_cond(e, st); return -1; }

    if (cfg->audit_file && *cfg->audit_file) {
        /* RMS directly: under /STANDARD=C99 fopen takes no RMS options. A shared
           sequential file, appended to by every process in the pool (SHRPUT), each
           record written with one $PUT at end of file. */
        afab = cc$rms_fab;
        afab.fab$l_fna = (char *) cfg->audit_file;
        afab.fab$b_fns = (unsigned char) strlen(cfg->audit_file);
        afab.fab$b_org = FAB$C_SEQ;
        afab.fab$b_rfm = FAB$C_VAR;
        afab.fab$b_rat = FAB$M_CR;
        afab.fab$b_fac = FAB$M_PUT;
        afab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT;
        afab.fab$l_fop = FAB$M_CIF;
        st = sys$create(&afab);
        if (st & 1) {
            arab = cc$rms_rab;
            arab.rab$l_fab = &afab;
            arab.rab$l_rop = RAB$M_EOF;
            st = sys$connect(&arab);
        }
        if (!(st & 1)) { set_cond(e, st); return -1; }
        audit_open = 1;
    }
    set_text(e, ST_OK, "");
    return 0;
}

/* ================================================================ sessions */

int st_plat_session_put(const st_session *s, st_err *e)
{
    unsigned char r[SR_LEN];
    unsigned int st;
    encode(s, r);
    srab.rab$b_rac = RAB$C_KEY;
    srab.rab$l_rop = RAB$M_UIF | RAB$M_WAT;   /* replace if present; wait out a lock */
    srab.rab$l_rbf = (char *) r;
    srab.rab$w_rsz = SR_LEN;
    st = sys$put(&srab);
    st_zero(r, sizeof r);
    sys$free(&srab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_session_get(const unsigned char key[32], st_session *s, st_err *e)
{
    unsigned char r[SR_LEN] = { 0 };
    unsigned int st;
    srab.rab$b_rac = RAB$C_KEY;
    srab.rab$b_krf = 0;
    srab.rab$l_kbf = (char *) key;
    srab.rab$b_ksz = 32;
    srab.rab$l_rop = RAB$M_NLK | RAB$M_RRL;
    srab.rab$l_ubf = (char *) r;
    srab.rab$w_usz = SR_LEN;
    st = sys$get(&srab);
    if (st == RMS$_RNF) return 0;
    if (!(st & 1)) { set_cond(e, st); return -1; }
    if (srab.rab$w_rsz != SR_LEN) return 0;   /* not a record we wrote: no session */
    decode(r, s);
    st_zero(r, sizeof r);
    return 1;
}

int st_plat_session_delete(const unsigned char key[32], st_err *e)
{
    unsigned int st;
    srab.rab$b_rac = RAB$C_KEY;
    srab.rab$b_krf = 0;
    srab.rab$l_kbf = (char *) key;
    srab.rab$b_ksz = 32;
    srab.rab$l_rop = RAB$M_WAT;
    st = sys$find(&srab);
    if (st == RMS$_RNF) return 0;
    if (st & 1) st = sys$delete(&srab);
    sys$free(&srab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

void st_plat_session_purge(long long created_before, long long seen_before)
{
    unsigned char r[SR_LEN] = { 0 };
    st_session s;
    if (!(sys$rewind(&srab) & 1)) return;
    srab.rab$b_rac = RAB$C_SEQ;
    srab.rab$l_rop = RAB$M_WAT;
    srab.rab$l_ubf = (char *) r;
    srab.rab$w_usz = SR_LEN;
    while (sys$get(&srab) & 1) {
        if (srab.rab$w_rsz != SR_LEN) continue;
        decode(r, &s);
        if (s.created < created_before || s.last_seen < seen_before) sys$delete(&srab);
    }
    st_zero(r, sizeof r);
    sys$free(&srab);
}

/* ================================================================ personas */

static unsigned int persona_handle;
static unsigned int persona_default[2];   /* what the persona started with */

/* Defaults plus enable (D9). A persona starts with the user's default privileges and
   $SETPRV may add any the user is authorized for, nothing more (probe_setprv): the
   persona's authorized mask, not the service's, is the ceiling. NOTALLPRIV, for a
   privilege no longer authorized, is not an error: the rest are still applied.
   Masks stay quadwords: PRV$M_ above bit 31 do not fit in a longword (PHASE1). */
int st_plat_persona_set_privs(const unsigned int enable[2], st_err *e)
{
    unsigned int off[2], st;
    if (!persona_handle) { set_text(e, ST_E_INTERNAL, "no persona"); return -1; }
    off[0] = ~persona_default[0];
    off[1] = ~persona_default[1];
    st = sys$setprv(0, (void *) off, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    if (enable[0] | enable[1]) {
        st = sys$setprv(1, (void *) enable, 0, 0);
        if (!(st & 1)) { set_cond(e, st); return -1; }
    }
    return 0;
}

int st_plat_persona_begin(const char *username, const unsigned int enable[2], st_err *e)
{
    struct dsc$descriptor_s d;
    unsigned int st, h = 0, iosb[2];
    st_ile3 items[2];
    if (persona_handle) { set_text(e, ST_E_INTERNAL, "a persona is already active"); return -1; }
    desc(&d, username, (unsigned short) strlen(username));
    {
        unsigned int on = sys$setprv(1, (void *) sysprv, 0, 0), off;
        st = sys$persona_create(&h, &d, 0, 0, 0);
        off = sys$setprv(0, (void *) sysprv, 0, 0);
        if (!(off & 1) || !st_plat_privileges_clean()) {
            st_plat_log("cannot disable SYSPRV after creating a persona; exiting");
            exit(44);
        }
        if (on == SS$_NOTALLPRIV && !(st & 1))
            st_plat_log("persona creation needs SYSPRV authorized for the service account (D2)");
    }
    if (!(st & 1)) { set_cond(e, st); return -1; }
    st = sys$persona_assume(&h, 0, 0, 0);
    if (!(st & 1)) { sys$persona_delete(&h); set_cond(e, st); return -1; }
    persona_handle = h;
    persona_default[0] = persona_default[1] = 0;
    item(&items[0], JPI$_CURPRIV, persona_default, 8, 0);
    item_end(&items[1]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    if (!(st & 1) || st_plat_persona_set_privs(enable, e)) {
        if (!(st & 1)) set_cond(e, st);
        st_plat_persona_end();
        return -1;
    }
    return 0;
}

void st_plat_persona_end(void)
{
    unsigned int natural = ISS$C_ID_NATURAL, st;
    if (!persona_handle) return;
    st = sys$persona_assume(&natural, 0, 0, 0);
    if (!(st & 1)) {
        /* Cannot get back to our own identity: nothing after this is safe. */
        st_plat_log("cannot revert to the natural persona; exiting");
        exit(44);
    }
    sys$persona_delete(&persona_handle);
    persona_handle = 0;
}

int st_plat_persona_active(void) { return persona_handle != 0; }

int st_plat_privileges_clean(void)
{
    unsigned int cur[2] = { 0, 0 }, iosb[2], st;
    st_ile3 items[2];
    if (persona_handle) return 1;   /* only the service's own identity is checked */
    item(&items[0], JPI$_CURPRIV, cur, 8, 0);
    item_end(&items[1]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    return (st & 1) && !(cur[0] & sysprv[0]) && !(cur[1] & sysprv[1]);
}

/* ================================================================ sign-in */

/* VMS times are 100 ns units since 17-NOV-1858 (quadwords). A password date of -1
   is AUTHORIZE's "pre-expired"; a lifetime is a negative delta, 0 meaning none. */
static int expired_now(unsigned int flags, const unsigned int pwd[2], const unsigned int pwd2[2],
                       const unsigned int life[2])
{
    unsigned int nowq[2];
    unsigned long long now, d1, d2;
    long long lt;
    if (flags & (UAI$M_PWD_EXPIRED | UAI$M_PWD2_EXPIRED)) return 1;
    d1 = ((unsigned long long) pwd[1] << 32) | pwd[0];
    d2 = ((unsigned long long) pwd2[1] << 32) | pwd2[0];
    if (d1 == ~0ull || d2 == ~0ull) return 1;
    lt = (long long) (((unsigned long long) life[1] << 32) | life[0]);
    if (lt == 0) return 0;
    if (lt < 0) lt = -lt;
    sys$gettim((void *) nowq);
    now = ((unsigned long long) nowq[1] << 32) | nowq[0];
    if (d1 && d1 + (unsigned long long) lt < now) return 1;
    if (d2 && d2 + (unsigned long long) lt < now) return 1;
    return 0;
}

/* Read the user's own expiry fields, as the user (probe_selfuai). */
static int check_expiry(const char *username, st_err *e)
{
    struct dsc$descriptor_s d;
    unsigned int flags = 0, st;
    unsigned int pwd[2] = {0, 0}, pwd2[2] = {0, 0}, life[2] = {0, 0};
    st_ile3 items[5];
    int exp;

    {
        static const unsigned int none[2] = { 0, 0 };
        if (st_plat_persona_begin(username, none, e)) return -1;
    }
    desc(&d, username, (unsigned short) strlen(username));
    item(&items[0], UAI$_FLAGS, &flags, 4, 0);
    item(&items[1], UAI$_PWD_DATE, pwd, 8, 0);
    item(&items[2], UAI$_PWD2_DATE, pwd2, 8, 0);
    item(&items[3], UAI$_PWD_LIFETIME, life, 8, 0);
    item_end(&items[4]);
    st = sys$getuai(0, 0, &d, items, 0, 0, 0);
    st_plat_persona_end();
    if (!(st & 1)) { set_cond(e, st); return -1; }
    exp = expired_now(flags, pwd, pwd2, life);
    if (exp) set_text(e, ST_OK, "password has expired");
    return exp;
}

int st_plat_authenticate(const char *username, const char *password,
                         const char *client, st_err *e)
{
    struct _acmesb sb;
    unsigned int st, ltype = ACME$K_NETWORK;
    st_ile3 items[6];
    int exp;

    memset(&sb, 0, sizeof sb);
    item(&items[0], ACME$_PRINCIPAL_NAME_IN, (void *) username, (unsigned short) strlen(username), 0);
    item(&items[1], ACME$_PASSWORD_1, (void *) password, (unsigned short) strlen(password), 0);
    item(&items[2], ACME$_LOGON_TYPE, &ltype, 4, 0);
    /* One intrusion record per browser address, not one for the whole service. */
    item(&items[3], ACME$_REMOTE_HOST_NAME, (void *) client, (unsigned short) strlen(client), 0);
    item(&items[4], ACME$_REMOTE_USERNAME, "STEWARD", 7, 0);
    item_end(&items[5]);

    st = sys$acmw(0, ACME$_FC_AUTHENTICATE_PRINCIPAL, 0, items, &sb, 0, 0);
    if (!(st & 1)) { set_cond(e, st); e->kind = ST_E_INTERNAL; return ST_AUTH_ERROR; }
    if (!(sb.acmesb$l_status & 1)) {
        /* The secondary status says why (LOGIN-F-INVPWD, LOGIN-F-DISUSER, ...): for
           the audit log only. */
        set_cond(e, sb.acmesb$l_secondary_status ? sb.acmesb$l_secondary_status
                                                 : sb.acmesb$l_status);
        e->kind = ST_OK;
        return ST_AUTH_FAILED;
    }
    exp = check_expiry(username, e);
    if (exp < 0) return ST_AUTH_ERROR;
    if (exp) return ST_AUTH_EXPIRED;
    set_text(e, ST_OK, "");
    return ST_AUTH_OK;
}

/* ================================================================ whoami */

int st_plat_whoami(st_whoami *w, st_err *e)
{
    char user[13], acct[9], owner[33];
    unsigned short ulen = 0, alen = 0, olen = 0, rlen = 0;
    unsigned int uic = 0, iosb[2], st, i;
    unsigned int rights[2 * ST_MAX_IDS * 2];   /* (id, attributes) pairs */
    struct dsc$descriptor_s d;
    st_ile3 items[8];

    if (!persona_handle) { set_text(e, ST_E_INTERNAL, "no persona"); return -1; }
    memset(w, 0, sizeof *w);
    item(&items[0], JPI$_USERNAME, user, 12, &ulen);
    item(&items[1], JPI$_UIC, &uic, 4, 0);
    item(&items[2], JPI$_AUTHPRIV, w->priv_auth, 8, 0);
    item(&items[3], JPI$_CURPRIV, w->priv_cur, 8, 0);
    item(&items[4], JPI$_ACCOUNT, acct, 8, &alen);
    item(&items[5], JPI$_PROCESS_RIGHTS, rights, sizeof rights, &rlen);
    item_end(&items[6]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    if (!(st & 1)) { set_cond(e, st); return -1; }

    user[ulen] = '\0';
    while (ulen && user[ulen - 1] == ' ') user[--ulen] = '\0';
    st_copy(w->username, sizeof w->username, user);
    acct[alen] = '\0';
    while (alen && acct[alen - 1] == ' ') acct[--alen] = '\0';
    st_copy(w->account, sizeof w->account, acct);
    w->uic = uic;
    w->priv_def[0] = persona_default[0];
    w->priv_def[1] = persona_default[1];

    /* Owner: the user's own UAF record, which a persona may read (probe_selfuai). */
    desc(&d, w->username, (unsigned short) strlen(w->username));
    item(&items[0], UAI$_OWNER, owner, 32, &olen);
    item_end(&items[1]);
    if ((sys$getuai(0, 0, &d, items, 0, 0, 0) & 1) && olen) {
        unsigned int n = (unsigned char) owner[0];   /* counted string */
        if (n > 31) n = 31;
        memcpy(w->owner, owner + 1, n);
        w->owner[n] = '\0';
    }

    /* Identifiers held: general identifiers (bit 31) from the process rights list. */
    for (i = 0; i + 1 < rlen / 4u && w->nids < ST_MAX_IDS; i += 2) {
        unsigned int id = rights[i], resid, attrib, ctx = 0;
        char name[32] = { 0 };
        unsigned short nlen = 0;
        if (!(id & 0x80000000u)) continue;
        desc(&d, name, sizeof name - 1);
        if (sys$idtoasc(id, &nlen, &d, &resid, &attrib, &ctx) & 1) {
            name[nlen] = '\0';
            st_copy(w->ids[w->nids++], sizeof w->ids[0], name);
        } else {
            snprintf(w->ids[w->nids++], sizeof w->ids[0], "%%X%08X", id);
        }
        sys$finish_rdb(&ctx);
    }
    return 0;
}

/* ================================================================ users

   Everything here runs under the caller's persona, so RMS and $GETUAI apply that
   user's rights: SYSUAF is (S:RWED,O:RWED,G,W), so listing needs SYSPRV or
   READALL, and $GETUAI allows the caller's own record, its group's with GRPPRV,
   anyone's with SYSPRV (PHASE0 #3, #4). */

/* VMS times: 100 ns units since 17-NOV-1858, in *local* time: SYSUAF stores them as
   the system clock read (PHASE2.md). OpenVMS keeps only the current offset from UTC
   (SYS$TIMEZONE_DIFFERENTIAL), and the C RTL here has no time zone rules
   (decc$fix_time returned local time unchanged), so the current offset is applied
   to every date: one from the other side of a daylight-saving change is an hour
   out, as it would be in any OpenVMS tool. 0 stays 0 ("none"), -1 stays -1
   (pre-expired). */
#define VMS_EPOCH_OFFSET 0x007C95674BEB4000ull   /* 1970-01-01 in VMS time */

static long long local_offset(void)
{
    unsigned int nowq[2] = { 0, 0 };
    unsigned long long v;
    long long local, diff;
    sys$gettim((void *) nowq);
    v = ((unsigned long long) nowq[1] << 32) | nowq[0];
    local = (long long) ((v - VMS_EPOCH_OFFSET) / 10000000ull);
    diff = local - (long long) time(NULL);
    /* Zones are whole quarter hours; rounding absorbs the gap between the reads. */
    return (diff >= 0 ? (diff + 450) / 900 : -((-diff + 450) / 900)) * 900;
}

static long long unix_time(const unsigned int q[2])
{
    unsigned long long v = ((unsigned long long) q[1] << 32) | q[0];
    if (v == 0) return 0;
    if (v == ~0ull) return -1;
    if (v < VMS_EPOCH_OFFSET) return 0;
    return (long long) ((v - VMS_EPOCH_OFFSET) / 10000000ull) - local_offset();
}

/* A counted string (length byte first) from $GETUAI, into out. */
static void counted(const char *buf, unsigned short retlen, char *out, size_t outlen)
{
    size_t n = retlen ? (unsigned char) buf[0] : 0;
    if (n > retlen - 1u) n = retlen ? retlen - 1u : 0;
    if (n >= outlen) n = outlen - 1;
    memcpy(out, buf + 1, n);
    out[n] = '\0';
    while (n && out[n - 1] == ' ') out[--n] = '\0';
}

static void blank_trim(const char *buf, size_t len, char *out, size_t outlen)
{
    size_t n = len < outlen - 1 ? len : outlen - 1;
    memcpy(out, buf, n);
    out[n] = '\0';
    while (n && (out[n - 1] == ' ' || out[n - 1] == '\0')) out[--n] = '\0';
}

/* UAI$_FLAGS bit by bit, from UAIDEF's own masks (DISUSER is UAI$M_DISACNT). */
static const struct { unsigned int mask; int bit; } uaf_flags[] = {
    { UAI$M_DISCTLY, ST_UF_DISCTLY }, { UAI$M_DEFCLI, ST_UF_DEFCLI },
    { UAI$M_LOCKPWD, ST_UF_LOCKPWD }, { UAI$M_RESTRICTED, ST_UF_RESTRICTED },
    { UAI$M_DISACNT, ST_UF_DISUSER }, { UAI$M_DISWELCOM, ST_UF_DISWELCOME },
    { UAI$M_DISMAIL, ST_UF_DISNEWMAIL }, { UAI$M_NOMAIL, ST_UF_DISMAIL },
    { UAI$M_GENPWD, ST_UF_GENPWD }, { UAI$M_PWD_EXPIRED, ST_UF_PWD_EXPIRED },
    { UAI$M_PWD2_EXPIRED, ST_UF_PWD2_EXPIRED }, { UAI$M_AUDIT, ST_UF_AUDIT },
    { UAI$M_DISREPORT, ST_UF_DISREPORT }, { UAI$M_DISRECONNECT, ST_UF_DISRECONNECT },
    { UAI$M_AUTOLOGIN, ST_UF_AUTOLOGIN }, { UAI$M_DISFORCE_PWD_CHANGE, ST_UF_DISFORCE_PWD_CHANGE },
    { UAI$M_CAPTIVE, ST_UF_CAPTIVE }, { UAI$M_DISIMAGE, ST_UF_DISIMAGE },
    { UAI$M_DISPWDDIC, ST_UF_DISPWDDIC }, { UAI$M_DISPWDHIS, ST_UF_DISPWDHIS },
    { UAI$M_DEFCLSVAL, ST_UF_DEFCLSVAL }, { UAI$M_EXTAUTH, ST_UF_EXTAUTH },
    { UAI$M_MIGRATEPWD, ST_UF_MIGRATEPWD }, { UAI$M_VMSAUTH, ST_UF_VMSAUTH },
    { UAI$M_DISPWDSYNCH, ST_UF_DISPWDSYNCH }, { UAI$M_PWDMIX, ST_UF_PWDMIX },
};

int st_plat_user_enum(const char *after, st_name_cb fn, void *ctx, st_err *e)
{
    struct FAB fab = cc$rms_fab;
    struct RAB rab = cc$rms_rab;
    static char rec[1412];   /* UAF$C_LENGTH is 644; room for longer records */
    char key[32], user[33];
    unsigned int st;

    fab.fab$l_fna = "SYSUAF";            fab.fab$b_fns = 6;
    fab.fab$l_dna = "SYS$SYSTEM:.DAT";   fab.fab$b_dns = 15;
    fab.fab$b_fac = FAB$M_GET;
    /* Shared, never locking a record: AUTHORIZE and LOGINOUT are never held up. */
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;
    st = sys$open(&fab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    rab.rab$l_fab = &fab;
    rab.rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    rab.rab$l_ubf = rec;
    rab.rab$w_usz = sizeof rec;
    st = sys$connect(&rab);
    if (!(st & 1)) { sys$close(&fab); set_cond(e, st); return -1; }

    if (after && *after) {   /* the first record past the cursor, by username (key 0) */
        size_t n = strlen(after);
        memset(key, ' ', sizeof key);
        memcpy(key, after, n > sizeof key ? sizeof key : n);
        rab.rab$b_rac = RAB$C_KEY;
        rab.rab$b_krf = 0;
        rab.rab$l_kbf = key;
        rab.rab$b_ksz = sizeof key;
        rab.rab$l_rop |= RAB$M_KGT;
        st = sys$get(&rab);
        rab.rab$b_rac = RAB$C_SEQ;
    } else {
        rab.rab$b_rac = RAB$C_SEQ;
        st = sys$get(&rab);
    }
    for (; st & 1; st = sys$get(&rab)) {
        if (rab.rab$w_rsz < 36) continue;
        blank_trim(rec + 4, 32, user, sizeof user);   /* UAF$T_USERNAME */
        if (!*user || strlen(user) > 12) continue;
        if (fn(user, ctx)) { st = RMS$_EOF; break; }
    }
    sys$disconnect(&rab);
    sys$close(&fab);
    if (st != RMS$_EOF && st != RMS$_RNF) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_user_get(const char *username, st_user *u, st_err *e)
{
    /* Quotas, in ST_Q_* order, with their item sizes. */
    static const struct { unsigned short code, size; } quotas[ST_Q_COUNT] = {
        { UAI$_PRI, 1 }, { UAI$_QUEPRI, 1 }, { UAI$_MAXJOBS, 2 }, { UAI$_MAXACCTJOBS, 2 },
        { UAI$_MAXDETACH, 2 }, { UAI$_PRCCNT, 2 }, { UAI$_BIOLM, 2 }, { UAI$_DIOLM, 2 },
        { UAI$_ASTLM, 2 }, { UAI$_TQCNT, 2 }, { UAI$_ENQLM, 2 }, { UAI$_FILLM, 2 },
        { UAI$_SHRFILLM, 2 }, { UAI$_BYTLM, 4 }, { UAI$_PBYTLM, 4 }, { UAI$_JTQUOTA, 4 },
        { UAI$_DFWSCNT, 4 }, { UAI$_WSQUOTA, 4 }, { UAI$_WSEXTENT, 4 }, { UAI$_PGFLQUOTA, 4 },
        { UAI$_CPUTIM, 4 },
    };
    static const unsigned short access_p[ST_ACC_COUNT] = {
        UAI$_NETWORK_ACCESS_P, UAI$_BATCH_ACCESS_P, UAI$_LOCAL_ACCESS_P,
        UAI$_DIALUP_ACCESS_P, UAI$_REMOTE_ACCESS_P };
    static const unsigned short access_s[ST_ACC_COUNT] = {
        UAI$_NETWORK_ACCESS_S, UAI$_BATCH_ACCESS_S, UAI$_LOCAL_ACCESS_S,
        UAI$_DIALUP_ACCESS_S, UAI$_REMOTE_ACCESS_S };
    char owner[32] = { 0 }, account[32] = { 0 }, cli[32] = { 0 }, tables[32] = { 0 };
    char defdev[32] = { 0 }, defdir[64] = { 0 }, lgicmd[256] = { 0 };
    unsigned short l_owner = 0, l_cli = 0, l_tables = 0, l_dev = 0, l_dir = 0, l_lgi = 0;
    unsigned int uic = 0, flags = 0, st, i, n = 0;
    unsigned int expq[2] = { 0, 0 }, lli[2] = { 0, 0 }, lln[2] = { 0, 0 };
    unsigned int pwd[2] = { 0, 0 }, pwd2[2] = { 0, 0 }, life[2] = { 0, 0 };
    unsigned int pwdlen = 0, logfails = 0, primedays = 0;
    unsigned int acc_p[ST_ACC_COUNT] = { 0 }, acc_s[ST_ACC_COUNT] = { 0 };
    unsigned int q[ST_Q_COUNT] = { 0 };
    struct dsc$descriptor_s d;
    st_ile3 items[30 + 2 * ST_ACC_COUNT + ST_Q_COUNT];

    memset(u, 0, sizeof *u);
    item(&items[n++], UAI$_OWNER, owner, sizeof owner, &l_owner);
    item(&items[n++], UAI$_ACCOUNT, account, sizeof account, 0);
    item(&items[n++], UAI$_UIC, &uic, 4, 0);
    item(&items[n++], UAI$_FLAGS, &flags, 4, 0);
    item(&items[n++], UAI$_DEFCLI, cli, sizeof cli, &l_cli);
    item(&items[n++], UAI$_CLITABLES, tables, sizeof tables, &l_tables);
    item(&items[n++], UAI$_DEFDEV, defdev, sizeof defdev, &l_dev);
    item(&items[n++], UAI$_DEFDIR, defdir, sizeof defdir, &l_dir);
    item(&items[n++], UAI$_LGICMD, lgicmd, sizeof lgicmd, &l_lgi);
    item(&items[n++], UAI$_EXPIRATION, expq, 8, 0);
    item(&items[n++], UAI$_LASTLOGIN_I, lli, 8, 0);
    item(&items[n++], UAI$_LASTLOGIN_N, lln, 8, 0);
    item(&items[n++], UAI$_PWD_DATE, pwd, 8, 0);
    item(&items[n++], UAI$_PWD2_DATE, pwd2, 8, 0);
    item(&items[n++], UAI$_PWD_LIFETIME, life, 8, 0);
    /* Smaller items land in the low bytes of a zeroed longword: little-endian on
       every OpenVMS architecture. */
    item(&items[n++], UAI$_PWD_LENGTH, &pwdlen, 1, 0);
    item(&items[n++], UAI$_LOGFAILS, &logfails, 2, 0);
    item(&items[n++], UAI$_PRIMEDAYS, &primedays, 1, 0);
    item(&items[n++], UAI$_PRIV, u->priv_auth, 8, 0);
    item(&items[n++], UAI$_DEF_PRIV, u->priv_def, 8, 0);
    for (i = 0; i < ST_ACC_COUNT; i++) {
        item(&items[n++], access_p[i], &acc_p[i], 3, 0);
        item(&items[n++], access_s[i], &acc_s[i], 3, 0);
    }
    for (i = 0; i < ST_Q_COUNT; i++) item(&items[n++], quotas[i].code, &q[i], quotas[i].size, 0);
    item_end(&items[n]);

    desc(&d, username, (unsigned short) strlen(username));
    st = sys$getuai(0, 0, &d, items, 0, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }

    st_copy(u->username, sizeof u->username, username);
    counted(owner, l_owner, u->owner, sizeof u->owner);
    blank_trim(account, 8, u->account, sizeof u->account);   /* blank-padded, not counted */
    counted(cli, l_cli, u->cli, sizeof u->cli);
    counted(tables, l_tables, u->clitables, sizeof u->clitables);
    counted(defdev, l_dev, u->defdev, sizeof u->defdev);
    counted(defdir, l_dir, u->defdir, sizeof u->defdir);
    counted(lgicmd, l_lgi, u->lgicmd, sizeof u->lgicmd);
    u->uic = uic;
    for (i = 0; i < sizeof uaf_flags / sizeof uaf_flags[0]; i++)
        if (flags & uaf_flags[i].mask) u->flags |= 1u << uaf_flags[i].bit;
    u->expiration = unix_time(expq);
    u->last_login_i = unix_time(lli);
    u->last_login_n = unix_time(lln);
    u->pwd_date = unix_time(pwd);
    u->pwd2_date = unix_time(pwd2);
    {
        long long lt = (long long) (((unsigned long long) life[1] << 32) | life[0]);
        if (lt < 0) lt = -lt;   /* a delta time */
        u->pwd_lifetime = lt / 10000000LL;
    }
    u->pwd_minimum = (int) pwdlen;
    u->login_fails = (int) logfails;
    u->secondary_days = primedays & 0x7F;   /* a set bit is a secondary day */
    for (i = 0; i < ST_ACC_COUNT; i++) {
        u->access_p[i] = acc_p[i] & 0xFFFFFF;
        u->access_s[i] = acc_s[i] & 0xFFFFFF;
    }
    for (i = 0; i < ST_Q_COUNT; i++) u->quota[i] = q[i];
    return 0;
}

/* ================================================================ identifiers

   $IDTOASC, $ASCTOID, $FIND_HELD and $FIND_HOLDER, under the persona. RIGHTSLIST
   is (S:RWED,O:RWED,G,W), so OpenVMS lets an unprivileged user see only the
   identifiers it holds. Every wildcard walk ends with $FINISH_RDB. */

static const struct { unsigned int mask; int bit; } kgb_attrs[] = {
    { KGB$M_RESOURCE, ST_IA_RESOURCE }, { KGB$M_DYNAMIC, ST_IA_DYNAMIC },
    { KGB$M_NOACCESS, ST_IA_NOACCESS }, { KGB$M_SUBSYSTEM, ST_IA_SUBSYSTEM },
    { KGB$M_IMPERSONATE, ST_IA_IMPERSONATE }, { KGB$M_HOLDER_HIDDEN, ST_IA_HOLDER_HIDDEN },
    { KGB$M_NAME_HIDDEN, ST_IA_NAME_HIDDEN },
};

static unsigned int attrib_bits(unsigned int kgb)
{
    unsigned int i, out = 0;
    for (i = 0; i < sizeof kgb_attrs / sizeof kgb_attrs[0]; i++)
        if (kgb & kgb_attrs[i].mask) out |= 1u << kgb_attrs[i].bit;
    return out;
}

/* The name of one identifier, or "" if the OS will not say. */
static void ident_name(unsigned int id, char out[32])
{
    char name[32] = { 0 };
    unsigned short nlen = 0;
    unsigned int resid = 0, attrib = 0, ctx = 0;
    struct dsc$descriptor_s d;
    desc(&d, name, sizeof name - 1);
    out[0] = '\0';
    if (sys$idtoasc(id, &nlen, &d, &resid, &attrib, &ctx) & 1) {
        name[nlen] = '\0';
        st_copy(out, 32, name);
    }
    sys$finish_rdb(&ctx);
}

int st_plat_ident_enum(st_ident_cb fn, void *ctx, st_err *e)
{
    unsigned int rdb = 0, st;
    for (;;) {
        char name[32] = { 0 };
        unsigned short nlen = 0;
        unsigned int id = 0, attrib = 0;
        struct dsc$descriptor_s d;
        st_ident out;
        desc(&d, name, sizeof name - 1);
        st = sys$idtoasc(0xFFFFFFFFu, &nlen, &d, &id, &attrib, &rdb);
        if (!(st & 1)) break;
        memset(&out, 0, sizeof out);
        name[nlen] = '\0';
        st_copy(out.name, sizeof out.name, name);
        out.value = id;
        out.attrib = attrib_bits(attrib);
        if (fn(&out, ctx)) { st = SS$_NOSUCHID; break; }
    }
    sys$finish_rdb(&rdb);
    if (st != SS$_NOSUCHID) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_ident_get(const char *name, st_ident *out, st_err *e)
{
    unsigned int id = 0, attrib = 0, st;
    struct dsc$descriptor_s d;
    desc(&d, name, (unsigned short) strlen(name));
    st = sys$asctoid(&d, &id, &attrib);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    memset(out, 0, sizeof *out);
    st_copy(out->name, sizeof out->name, name);
    out->value = id;
    out->attrib = attrib_bits(attrib);
    return 0;
}

int st_plat_ident_held(unsigned int uic, st_ident_cb fn, void *ctx, st_err *e)
{
    unsigned int holder[2], rdb = 0, st;
    holder[0] = uic;
    holder[1] = 0;
    for (;;) {
        unsigned int id = 0, attrib = 0;
        st_ident out;
        st = sys$find_held((void *) holder, &id, &attrib, &rdb);
        if (!(st & 1)) break;
        memset(&out, 0, sizeof out);
        ident_name(id, out.name);
        out.value = id;
        out.attrib = attrib_bits(attrib);
        if (fn(&out, ctx)) { st = SS$_NOSUCHID; break; }
    }
    sys$finish_rdb(&rdb);
    if (st != SS$_NOSUCHID) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_ident_holders(unsigned int value, st_ident_cb fn, void *ctx, st_err *e)
{
    unsigned int holder[2], rdb = 0, st;
    for (;;) {
        unsigned int attrib = 0;
        st_ident out;
        holder[0] = holder[1] = 0;
        st = sys$find_holder(value, (void *) holder, &attrib, &rdb);
        if (!(st & 1)) break;
        memset(&out, 0, sizeof out);
        ident_name(holder[0], out.name);
        out.value = holder[0];
        out.attrib = attrib_bits(attrib);
        if (fn(&out, ctx)) { st = SS$_NOSUCHID; break; }
    }
    sys$finish_rdb(&rdb);
    if (st != SS$_NOSUCHID) { set_cond(e, st); return -1; }
    return 0;
}

/* ================================================================ changes (Phase 3)

   All under the caller's persona: OpenVMS refuses what the user may not do
   (probe_modify). Each user change is one $SETUAI call, so it applies whole or not
   at all. */

/* A counted field at its declared size: length byte, text, blank fill. A shorter
   buffer is refused with BADPARAM (PHASE3.md, finding 1). */
static void counted_put(char *buf, size_t size, const char *text)
{
    size_t n = strlen(text);
    if (n > size - 1) n = size - 1;
    memset(buf, ' ', size);
    buf[0] = (char) n;
    memcpy(buf + 1, text, n);
}

/* Seconds since 1970 UTC to a VMS local-time quadword (the reverse of unix_time). */
static void vms_time(long long t, unsigned int q[2])
{
    unsigned long long v = 0;
    if (t > 0) v = (unsigned long long) (t + local_offset()) * 10000000ull + VMS_EPOCH_OFFSET;
    q[0] = (unsigned int) v;
    q[1] = (unsigned int) (v >> 32);
}

int st_plat_user_modify(const char *username, const st_user_change *c, st_err *e)
{
    static const struct { unsigned short code, size; } quotas[ST_Q_COUNT] = {
        { UAI$_PRI, 1 }, { UAI$_QUEPRI, 1 }, { UAI$_MAXJOBS, 2 }, { UAI$_MAXACCTJOBS, 2 },
        { UAI$_MAXDETACH, 2 }, { UAI$_PRCCNT, 2 }, { UAI$_BIOLM, 2 }, { UAI$_DIOLM, 2 },
        { UAI$_ASTLM, 2 }, { UAI$_TQCNT, 2 }, { UAI$_ENQLM, 2 }, { UAI$_FILLM, 2 },
        { UAI$_SHRFILLM, 2 }, { UAI$_BYTLM, 4 }, { UAI$_PBYTLM, 4 }, { UAI$_JTQUOTA, 4 },
        { UAI$_DFWSCNT, 4 }, { UAI$_WSQUOTA, 4 }, { UAI$_WSEXTENT, 4 }, { UAI$_PGFLQUOTA, 4 },
        { UAI$_CPUTIM, 4 },
    };
    static const unsigned short access_p[ST_ACC_COUNT] = {
        UAI$_NETWORK_ACCESS_P, UAI$_BATCH_ACCESS_P, UAI$_LOCAL_ACCESS_P,
        UAI$_DIALUP_ACCESS_P, UAI$_REMOTE_ACCESS_P };
    static const unsigned short access_s[ST_ACC_COUNT] = {
        UAI$_NETWORK_ACCESS_S, UAI$_BATCH_ACCESS_S, UAI$_LOCAL_ACCESS_S,
        UAI$_DIALUP_ACCESS_S, UAI$_REMOTE_ACCESS_S };
    char owner[32], account[32], cli[32], tables[32], defdev[32], defdir[64], lgicmd[64];
    unsigned int flags = 0, expq[2], life[2], pwdlen, days, acc_p[ST_ACC_COUNT], acc_s[ST_ACC_COUNT];
    unsigned int q[ST_Q_COUNT], pa[2], pd[2], st, i, n = 0;
    struct dsc$descriptor_s d;
    st_ile3 items[16 + 2 * ST_ACC_COUNT + ST_Q_COUNT];

    desc(&d, username, (unsigned short) strlen(username));
    if (c->fields & ST_UC_OWNER) { counted_put(owner, sizeof owner, c->owner); item(&items[n++], UAI$_OWNER, owner, sizeof owner, 0); }
    if (c->fields & ST_UC_ACCOUNT) {   /* blank-padded, not counted */
        size_t l = strlen(c->account);
        memset(account, ' ', sizeof account);
        memcpy(account, c->account, l > 8 ? 8 : l);
        item(&items[n++], UAI$_ACCOUNT, account, sizeof account, 0);
    }
    if (c->fields & ST_UC_CLI) { counted_put(cli, sizeof cli, c->cli); item(&items[n++], UAI$_DEFCLI, cli, sizeof cli, 0); }
    if (c->fields & ST_UC_CLITABLES) { counted_put(tables, sizeof tables, c->clitables); item(&items[n++], UAI$_CLITABLES, tables, sizeof tables, 0); }
    if (c->fields & ST_UC_DEFDEV) { counted_put(defdev, sizeof defdev, c->defdev); item(&items[n++], UAI$_DEFDEV, defdev, sizeof defdev, 0); }
    if (c->fields & ST_UC_DEFDIR) { counted_put(defdir, sizeof defdir, c->defdir); item(&items[n++], UAI$_DEFDIR, defdir, sizeof defdir, 0); }
    if (c->fields & ST_UC_LGICMD) { counted_put(lgicmd, sizeof lgicmd, c->lgicmd); item(&items[n++], UAI$_LGICMD, lgicmd, sizeof lgicmd, 0); }
    if (c->fields & ST_UC_FLAGS) {
        /* Read, then change only the bits Steward knows: a flag added in a later
           OpenVMS version survives an edit made here. */
        st_ile3 get[2];
        item(&get[0], UAI$_FLAGS, &flags, 4, 0);
        item_end(&get[1]);
        st = sys$getuai(0, 0, &d, get, 0, 0, 0);
        if (!(st & 1)) { set_cond(e, st); return -1; }
        for (i = 0; i < sizeof uaf_flags / sizeof uaf_flags[0]; i++) {
            flags &= ~uaf_flags[i].mask;
            if (c->flags & (1u << uaf_flags[i].bit)) flags |= uaf_flags[i].mask;
        }
        item(&items[n++], UAI$_FLAGS, &flags, 4, 0);
    }
    if (c->fields & ST_UC_EXPIRATION) { vms_time(c->expiration, expq); item(&items[n++], UAI$_EXPIRATION, expq, 8, 0); }
    if (c->fields & ST_UC_PWD_LIFETIME) {   /* a delta time: negative */
        long long v = -(c->pwd_lifetime * 10000000LL);
        life[0] = (unsigned int) v;
        life[1] = (unsigned int) ((unsigned long long) v >> 32);
        item(&items[n++], UAI$_PWD_LIFETIME, life, 8, 0);
    }
    if (c->fields & ST_UC_PWD_MINIMUM) { pwdlen = (unsigned int) c->pwd_minimum; item(&items[n++], UAI$_PWD_LENGTH, &pwdlen, 1, 0); }
    if (c->fields & ST_UC_DAYS) { days = c->secondary_days & 0x7F; item(&items[n++], UAI$_PRIMEDAYS, &days, 1, 0); }
    if (c->fields & ST_UC_ACCESS)
        for (i = 0; i < ST_ACC_COUNT; i++) {
            acc_p[i] = c->access_p[i] & 0xFFFFFF;
            acc_s[i] = c->access_s[i] & 0xFFFFFF;
            item(&items[n++], access_p[i], &acc_p[i], 3, 0);
            item(&items[n++], access_s[i], &acc_s[i], 3, 0);
        }
    if (c->fields & ST_UC_PRIV_AUTH) { pa[0] = c->priv_auth[0]; pa[1] = c->priv_auth[1]; item(&items[n++], UAI$_PRIV, pa, 8, 0); }
    if (c->fields & ST_UC_PRIV_DEF) { pd[0] = c->priv_def[0]; pd[1] = c->priv_def[1]; item(&items[n++], UAI$_DEF_PRIV, pd, 8, 0); }
    if (c->fields & ST_UC_QUOTAS)
        for (i = 0; i < ST_Q_COUNT; i++)
            if (c->quota_mask & (1u << i)) {
                q[i] = (unsigned int) c->quota[i];
                item(&items[n++], quotas[i].code, &q[i], quotas[i].size, 0);
            }
    item_end(&items[n]);
    if (n == 0) return 0;
    st = sys$setuai(0, 0, &d, items, 0, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_user_set_password(const char *username, const char *password, int pre_expired,
                              st_err *e)
{
    struct dsc$descriptor_s d;
    st_ile3 items[2];
    unsigned int st;
    desc(&d, username, (unsigned short) strlen(username));
    /* Plaintext: the system hashes it with the preferred algorithm and applies the
       account's minimum length (PHASE3.md). It sets the password date to now. */
    item(&items[0], UAI$_PASSWORD, (void *) password, (unsigned short) strlen(password), 0);
    item_end(&items[1]);
    st = sys$setuai(0, 0, &d, items, 0, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    if (pre_expired) {   /* AUTHORIZE's /PWDEXPIRED: a password date of -1 */
        unsigned int never[2] = { 0xFFFFFFFFu, 0xFFFFFFFFu };
        item(&items[0], UAI$_PWD_DATE, never, 8, 0);
        st = sys$setuai(0, 0, &d, items, 0, 0, 0);
        if (!(st & 1)) {
            set_cond(e, st);
            st_copy(e->text, sizeof e->text, "the password was set, but marking it expired failed");
            e->kind = ST_E_INTERNAL;
            return -1;
        }
    }
    return 0;
}

int st_plat_change_password(const char *username, const char *current, const char *newpw,
                            const char *client, st_err *e)
{
    struct _acmesb sb;
    unsigned int st, ltype = ACME$K_NETWORK, pflags = 0;
    st_ile3 items[8];

    if (persona_handle) { set_text(e, ST_E_INTERNAL, "a persona is active"); return ST_AUTH_ERROR; }
    {
        /* The account's minimum length, read as the user (its own record needs no
           privilege: probe_selfuai), so a short password gets a clear answer.
           Without SYSPRV, $ACM would say only AUTHFAILURE (PHASE3.md). */
        static const unsigned int none[2] = { 0, 0 };
        unsigned int minlen = 0;
        struct dsc$descriptor_s d;
        st_ile3 it[2];
        if (st_plat_persona_begin(username, none, e)) return ST_AUTH_ERROR;
        desc(&d, username, (unsigned short) strlen(username));
        item(&it[0], UAI$_PWD_LENGTH, &minlen, 1, 0);
        item_end(&it[1]);
        st = sys$getuai(0, 0, &d, it, 0, 0, 0);
        st_plat_persona_end();
        if ((st & 1) && strlen(newpw) < minlen) {
            set_cond(e, SS$_INVPWDLEN);
            snprintf(e->text, sizeof e->text, "%%SYSTEM-F-INVPWDLEN, the new password must be at least %u characters", minlen);
            return ST_AUTH_FAILED;
        }
    }
    memset(&sb, 0, sizeof sb);
    item(&items[0], ACME$_PRINCIPAL_NAME_IN, (void *) username, (unsigned short) strlen(username), 0);
    item(&items[1], ACME$_PASSWORD_1, (void *) current, (unsigned short) strlen(current), 0);
    item(&items[2], ACME$_NEW_PASSWORD_1, (void *) newpw, (unsigned short) strlen(newpw), 0);
    item(&items[3], ACME$_LOGON_TYPE, &ltype, 4, 0);
    item(&items[4], ACME$_REMOTE_HOST_NAME, (void *) client, (unsigned short) strlen(client), 0);
    item(&items[5], ACME$_REMOTE_USERNAME, "STEWARD", 7, 0);
    /* Required in non-dialogue mode: without it, INSFARG (probe_acmchg). */
    item(&items[6], ACME$_NEW_PASSWORD_FLAGS, &pflags, 4, 0);
    item_end(&items[7]);
    st = sys$acmw(0, ACME$_FC_CHANGE_PASSWORD, 0, items, &sb, 0, 0);
    if (!(st & 1)) { set_cond(e, st); e->kind = ST_E_INTERNAL; return ST_AUTH_ERROR; }
    if (!(sb.acmesb$l_status & 1)) {
        /* The caller has just checked the current password, so this is about the new
           one: history, dictionary or another policy. Without SYSPRV the reason is
           often only AUTHFAILURE (PHASE3.md). */
        set_cond(e, sb.acmesb$l_secondary_status ? sb.acmesb$l_secondary_status
                                                 : sb.acmesb$l_status);
        e->kind = ST_E_INVALID;
        return ST_AUTH_FAILED;
    }
    set_text(e, ST_OK, "");
    return ST_AUTH_OK;
}

static unsigned int kgb_bits(unsigned int attrib)
{
    unsigned int i, kgb = 0;
    for (i = 0; i < sizeof kgb_attrs / sizeof kgb_attrs[0]; i++)
        if (attrib & (1u << kgb_attrs[i].bit)) kgb |= kgb_attrs[i].mask;
    return kgb;
}

int st_plat_ident_add(const char *name, unsigned int value, unsigned int attrib,
                      st_ident *out, st_err *e)
{
    struct dsc$descriptor_s d;
    unsigned int id = 0, st;
    desc(&d, name, (unsigned short) strlen(name));
    st = sys$add_ident(&d, value, kgb_bits(attrib), &id);   /* value 0: OpenVMS chooses */
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return st_plat_ident_get(name, out, e);
}

int st_plat_ident_modify(unsigned int value, const char *new_name, unsigned int set,
                         unsigned int clear, st_err *e)
{
    struct dsc$descriptor_s d;
    unsigned int st;
    desc(&d, new_name ? new_name : "", (unsigned short) (new_name ? strlen(new_name) : 0));
    st = sys$mod_ident(value, kgb_bits(set), kgb_bits(clear),
                       (new_name && *new_name) ? &d : 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_ident_remove(unsigned int value, st_err *e)
{
    unsigned int st = sys$rem_ident(value);   /* takes its holder records with it */
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_holder_add(unsigned int value, unsigned int uic, unsigned int attrib, st_err *e)
{
    unsigned int holder[2], st;
    holder[0] = uic;
    holder[1] = 0;
    st = sys$add_holder(value, (void *) holder, kgb_bits(attrib));
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_holder_modify(unsigned int value, unsigned int uic, unsigned int set,
                          unsigned int clear, st_err *e)
{
    unsigned int holder[2], st;
    holder[0] = uic;
    holder[1] = 0;
    st = sys$mod_holder(value, (void *) holder, kgb_bits(set), kgb_bits(clear));
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_holder_remove(unsigned int value, unsigned int uic, st_err *e)
{
    unsigned int holder[2], st;
    holder[0] = uic;
    holder[1] = 0;
    st = sys$rem_holder(value, (void *) holder);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

/* ================================================================ the system (dashboard)

   The figures vms-fastfetch shows, from the same services and with its findings
   (github.com/issinoho/vms-fastfetch, docs/DECISIONS.md and docs/PROBES.md):
   - memory: SYI$_MEMSIZE pages; the free and modified lists from $GETRMI (D7);
   - CPU: RMI$_CPUIDLE ticks, 100 a second per CPU; the process-state counts
     RMI$_CUR/COM/COMO need a 4-byte buffer, 8 gives BADPARAM (D15);
   - disks: $DEVICE_SCAN for disks, skipping foreign, shadow-set members, served
     devices and memory-disk boot images (SYS$MD*);
   - processes: a wildcard $GETJPI, counting NOPRIV/SUSPENDED as hidden;
   - queues: $GETQUI, whose IOSB starts with a longword condition (JBC$_ codes).
   All of it under the caller's persona. */

/* One item from $GETSYI ($GETRMI when rmi), into a zeroed 8-byte value. Give an
   8-byte buffer (size 8), as fastfetch does: with 4, RMI$_FRLIST and the page-file
   items came back as 0 on the x86 node. RMI$_CUR, COM and COMO are the exceptions:
   they need exactly 4 (8 gives BADPARAM). */
static unsigned int item_u64(int rmi, unsigned short code, unsigned short size, unsigned long long *out)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    unsigned char buf[8] = { 0 };
    unsigned short len = 0;
    st_ile3 it[2];
    item(&it[0], code, buf, size, &len);
    item_end(&it[1]);
    if (rmi) {
        st = sys$getrmi(0, 0, 0, it, iosb, 0, 0);
        if (st & 1) st = sys$synch(0, iosb);
    } else {
        st = sys$getsyiw(0, 0, 0, it, iosb, 0, 0);
    }
    if (st & 1) st = iosb[0] & 0xFFFF;
    *out = 0;
    if (st & 1) memcpy(out, buf, len > 8 ? 8 : len);   /* little-endian on IA64 and x86-64 */
    return st;
}

static void syi_str(unsigned short code, char *out, size_t outlen)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    char buf[256] = { 0 };
    unsigned short len = 0;
    size_t i, o = 0;
    st_ile3 it[2];
    item(&it[0], code, buf, sizeof buf - 1, &len);
    item_end(&it[1]);
    st = sys$getsyiw(0, 0, 0, it, iosb, 0, 0);
    out[0] = '\0';
    if (!(st & 1) || !(iosb[0] & 1)) return;
    for (i = 0; i < len && o + 1 < outlen; i++) {   /* runs of blanks collapsed (IA64 pads) */
        if (buf[i] == ' ' && (o == 0 || out[o - 1] == ' ')) continue;
        out[o++] = buf[i];
    }
    while (o && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

static unsigned int dvi_item(const char *dev, unsigned short code, void *buf, unsigned short size,
                             unsigned short *len)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    struct dsc$descriptor_s d;
    st_ile3 it[2];
    desc(&d, dev, (unsigned short) strlen(dev));
    item(&it[0], code, buf, size, len);
    item_end(&it[1]);
    st = sys$getdviw(0, 0, &d, it, iosb, 0, 0, 0);
    if (st & 1) st = iosb[0] & 0xFFFF;
    return st;
}

static unsigned int dvi_u32(const char *dev, unsigned short code)
{
    unsigned int v = 0;
    unsigned short len = 0;
    return (dvi_item(dev, code, &v, 4, &len) & 1) ? v : 0;
}

static void dvi_str(const char *dev, unsigned short code, char *out, size_t outlen)
{
    char buf[65] = { 0 };
    unsigned short len = 0;
    out[0] = '\0';
    if (dvi_item(dev, code, buf, sizeof buf - 1, &len) & 1) blank_trim(buf, len, out, outlen);
}

static const char *acp_name(unsigned int acp)
{
    switch (acp) {
    case 1: return "ODS-1";
    case 2: return "ODS-2";
    case 7: return "ODS-3";
    case 8: return "ODS-4";
    case 11: return "ODS-5";
    case 12: return "ODS-6";
    default: return "";
    }
}

static void system_disks(st_system *s)
{
    char name[65], sysdev[65], full[65];
    unsigned short len;
    unsigned int devclass = DC$_DISK, ctx[2] = { 0, 0 }, st;
    struct dsc$descriptor_s nd;
    st_ile3 sel[2];
    int i;

    dvi_str("SYS$SYSDEVICE", DVI$_FULLDEVNAM, sysdev, sizeof sysdev);
    item(&sel[0], DVS$_DEVCLASS, &devclass, sizeof devclass, 0);
    item_end(&sel[1]);
    for (;;) {
        st_disk *d;
        const char *p;
        unsigned long long maxblock, freeblocks;
        len = 0;
        desc(&nd, name, sizeof name - 1);
        st = sys$device_scan(&nd, &len, 0, sel, (void *) ctx);
        if (!(st & 1)) break;
        name[len] = '\0';
        if (!dvi_u32(name, DVI$_MNT) || dvi_u32(name, DVI$_FOR) || dvi_u32(name, DVI$_SHDW_MEMBER) ||
            dvi_u32(name, DVI$_REMOTE_DEVICE))
            continue;
        if (s->ndisks == ST_MAX_DISKS) break;
        d = &s->disks[s->ndisks];
        memset(d, 0, sizeof *d);
        dvi_str(name, DVI$_VOLNAM, d->label, sizeof d->label);
        dvi_str(name, DVI$_LOGVOLNAM, d->logical_volume, sizeof d->logical_volume);
        if (!strncmp(d->logical_volume, "SYS$MD", 6)) continue;   /* memory-disk boot image */
        dvi_str(name, DVI$_FULLDEVNAM, full, sizeof full);
        p = strchr(full, '$');                                    /* "_NODE$DKA0:" -> "DKA0:" */
        p = p ? p + 1 : (full[0] == '_' ? full + 1 : full);
        st_copy(d->device, sizeof d->device, p);
        st_copy(d->filesystem, sizeof d->filesystem, acp_name(dvi_u32(name, DVI$_ACPTYPE)));
        maxblock = dvi_u32(name, DVI$_MAXBLOCK);
        freeblocks = dvi_u32(name, DVI$_FREEBLOCKS);
        d->total = maxblock * 512ull;
        d->free = freeblocks * 512ull;
        d->system_disk = !strcmp(full, sysdev);
        s->ndisks++;
    }
    for (i = 1; i < s->ndisks; i++)   /* the system disk first */
        if (s->disks[i].system_disk) {
            st_disk t = s->disks[i];
            memmove(&s->disks[1], &s->disks[0], (size_t) i * sizeof t);
            s->disks[0] = t;
            break;
        }
}

static void system_processes(st_system *s)
{
    unsigned int ctx = 0xFFFFFFFFu, mode, owner, iosb[2], st;
    char user[13];
    unsigned short l1, l2, l3;
    st_ile3 it[4];
    int i;
    item(&it[0], JPI$_MODE, &mode, 4, &l1);
    item(&it[1], JPI$_OWNER, &owner, 4, &l2);
    item(&it[2], JPI$_USERNAME, user, 12, &l3);
    item_end(&it[3]);
    for (;;) {
        mode = owner = 0;
        l3 = 0;
        st = sys$getjpiw(0, &ctx, 0, it, iosb, 0, 0);
        if (st & 1) st = iosb[0] & 0xFFFF;
        if (st == SS$_NOMOREPROC) break;
        if (st == SS$_NOPRIV || st == SS$_SUSPENDED) { s->processes_hidden++; continue; }
        if (!(st & 1)) break;
        s->processes++;
        if (mode == JPI$K_INTERACTIVE && owner == 0) {   /* a session; subprocesses are not */
            char u[13];
            blank_trim(user, l3, u, sizeof u);
            for (i = 0; i < s->nsessions && strcmp(s->sessions[i].username, u); i++) ;
            if (i < s->nsessions) s->sessions[i].sessions++;
            else if (s->nsessions < ST_MAX_SESSIONS) {
                st_copy(s->sessions[s->nsessions].username, sizeof s->sessions[0].username, u);
                s->sessions[s->nsessions++].sessions = 1;
            }
        }
    }
}

static void system_queues(st_system *s)
{
    static char search[] = "*";
    unsigned int ctx = 0xFFFFFFFFu, flags, status, executing, pending, holding, timed;
    unsigned int iosb[2], st;   /* a longword condition first: JBC$_ codes (fastfetch) */
    unsigned short l[6];
    st_ile3 it[8];
    item(&it[0], QUI$_SEARCH_NAME, search, 1, 0);
    item(&it[1], QUI$_QUEUE_FLAGS, &flags, 4, &l[0]);
    item(&it[2], QUI$_QUEUE_STATUS, &status, 4, &l[1]);
    item(&it[3], QUI$_EXECUTING_JOB_COUNT, &executing, 4, &l[2]);
    item(&it[4], QUI$_PENDING_JOB_COUNT, &pending, 4, &l[3]);
    item(&it[5], QUI$_HOLDING_JOB_COUNT, &holding, 4, &l[4]);
    item(&it[6], QUI$_TIMED_RELEASE_JOB_COUNT, &timed, 4, &l[5]);
    item_end(&it[7]);
    for (;;) {
        flags = status = executing = pending = holding = timed = 0;
        st = sys$getquiw(0, QUI$_DISPLAY_QUEUE, &ctx, it, iosb, 0, 0);
        if (st & 1) st = iosb[0];
        if (!(st & 1)) break;   /* JBC$_NOMOREQUE, or a refusal */
        s->queues++;
        if (flags & QUI$M_QUEUE_BATCH) s->queues_batch++; else s->queues_output++;
        if (status & QUI$M_QUEUE_STOPPED) s->queues_stopped++;
        s->jobs_executing += executing;
        s->jobs_pending += pending;
        s->jobs_holding += holding;
        s->jobs_timed += timed;
    }
    sys$getquiw(0, QUI$_CANCEL_OPERATION, &ctx, 0, iosb, 0, 0);
}

int st_plat_system(st_system *s, st_err *e)
{
    unsigned long long v, pages = 0, pagesize = 0, fr = 0, mod = 0, pf = 0, pff = 0, sf = 0, sff = 0;
    unsigned int boot[2], nowq[2] = { 0, 0 };

    memset(s, 0, sizeof *s);
    syi_str(SYI$_NODENAME, s->node, sizeof s->node);
    syi_str(SYI$_VERSION, s->version, sizeof s->version);
    syi_str(SYI$_ARCH_NAME, s->arch, sizeof s->arch);
    syi_str(SYI$_HW_NAME, s->hardware, sizeof s->hardware);
    if (!*s->node) { set_text(e, ST_E_INTERNAL, "$GETSYI failed"); return -1; }
    if (item_u64(0, SYI$_VIRTUAL_MACHINE, 8, &v) & 1) s->virtual_machine = v != 0;
    if (item_u64(0, SYI$_BOOTTIME, 8, &v) & 1) {
        boot[0] = (unsigned int) v;
        boot[1] = (unsigned int) (v >> 32);
        s->boot_time = unix_time(boot);
    }
    if (item_u64(0, SYI$_ACTIVECPU_CNT, 8, &v) & 1) s->cpus_active = (unsigned int) v;
    if (item_u64(0, SYI$_AVAILCPU_CNT, 8, &v) & 1) s->cpus_available = (unsigned int) v;
    item_u64(1, RMI$_CPUIDLE, 8, &s->cpu_idle_ticks);
    /* When the idle ticks were read, in UTC milliseconds ($GETTIM is local time; no
       struct timeval under /STANDARD=C99). */
    sys$gettim((void *) nowq);
    s->sampled_at_ms = (long long) ((((unsigned long long) nowq[1] << 32 | nowq[0]) - VMS_EPOCH_OFFSET) / 10000ull)
                       - local_offset() * 1000;
    if (item_u64(1, RMI$_CUR, 4, &v) & 1) s->load_current = (unsigned int) v;
    if (item_u64(1, RMI$_COM, 4, &v) & 1) s->load_computable = (unsigned int) v;
    if (item_u64(1, RMI$_COMO, 4, &v) & 1) s->load_computable_out = (unsigned int) v;
    item_u64(0, SYI$_MEMSIZE, 8, &pages);
    item_u64(0, SYI$_PAGE_SIZE, 8, &pagesize);
    item_u64(1, RMI$_FRLIST, 8, &fr);
    item_u64(1, RMI$_MODLIST, 8, &mod);
    s->mem_total = pages * pagesize;
    s->mem_free = fr * pagesize;
    s->mem_modified = mod * pagesize;
    item_u64(0, SYI$_PAGEFILE_PAGE, 8, &pf);
    item_u64(0, SYI$_PAGEFILE_FREE, 8, &pff);
    item_u64(0, SYI$_SWAPFILE_PAGE, 8, &sf);
    item_u64(0, SYI$_SWAPFILE_FREE, 8, &sff);
    s->page_total = (pf + sf) * pagesize;
    s->page_used = (pf + sf > pff + sff ? pf + sf - pff - sff : 0) * pagesize;
    system_disks(s);
    system_processes(s);
    system_queues(s);
    if ((item_u64(0, SYI$_CLUSTER_MEMBER, 8, &v) & 1) && (v & 1)) {
        s->cluster_member = 1;
        if (item_u64(0, SYI$_CLUSTER_NODES, 8, &v) & 1) s->cluster_nodes = (unsigned int) v;
        if (item_u64(0, SYI$_CLUSTER_VOTES, 8, &v) & 1) s->cluster_votes = (unsigned int) v;
        if (item_u64(0, SYI$_CLUSTER_QUORUM, 8, &v) & 1) s->cluster_quorum = (unsigned int) v;
    }
    return 0;
}

/* ================================================================ create and delete (D6)

   As AUTHORIZE ADD, COPY and REMOVE, verified identical by probe_uafcreate
   (PHASE4.md). The record is UAFDEF's own struct (SYS$LIB_C.TLB): the compiler lays
   it out exactly as the system does. Under the caller's persona: OpenVMS refuses a
   caller without write access to SYSUAF. */

static unsigned int uaf_open(struct FAB *fab, struct RAB *rab, UAF *rec)
{
    unsigned int st;
    *fab = cc$rms_fab;
    *rab = cc$rms_rab;
    fab->fab$l_fna = "SYSUAF";           fab->fab$b_fns = 6;
    fab->fab$l_dna = "SYS$SYSTEM:.DAT";  fab->fab$b_dns = 15;
    fab->fab$b_fac = FAB$M_GET | FAB$M_PUT | FAB$M_DEL | FAB$M_UPD;
    fab->fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;
    st = sys$open(fab);
    if (!(st & 1)) return st;
    rab->rab$l_fab = fab;
    rab->rab$l_ubf = (char *) rec;
    rab->rab$w_usz = sizeof *rec;
    st = sys$connect(rab);
    if (!(st & 1)) sys$close(fab);
    return st;
}

static void uaf_key(char key[32], const char *username)
{
    size_t n = strlen(username);
    memset(key, ' ', 32);
    memcpy(key, username, n > 32 ? 32 : n);
}

/* Remove a user record by username, from an open SYSUAF. */
static unsigned int uaf_delete_open(struct RAB *rab, const char *username)
{
    static char key[32];   /* static: the RAB keeps pointing at it (cppcheck autoVariables) */
    unsigned int st;
    uaf_key(key, username);
    rab->rab$b_rac = RAB$C_KEY; rab->rab$b_krf = 0; rab->rab$l_kbf = key; rab->rab$b_ksz = 32;
    rab->rab$l_rop = 0;                         /* lock the record: it is being deleted */
    st = sys$find(rab);
    if (st & 1) st = sys$delete(rab);
    return st;
}

/* Undo a create that failed after the record was written. */
static void create_undo(const char *username, unsigned int uic, int ident_added)
{
    struct FAB fab;
    struct RAB rab;
    static UAF rec;
    if (ident_added) sys$rem_ident(uic);
    if (uaf_open(&fab, &rab, &rec) & 1) {
        uaf_delete_open(&rab, username);
        sys$close(&fab);
    }
}

int st_plat_user_create(st_user_new *n, st_err *e)
{
    struct FAB fab;
    struct RAB rab;
    static UAF rec;
    char key[32], name[32] = { 0 };
    unsigned int st, id = 0, attrib = 0, resid = 0, ctx = 0;
    unsigned short nlen = 0;
    struct dsc$descriptor_s d;
    size_t plen = strlen(n->password);

    n->warning[0] = '\0';
    /* Nothing of the name or the UIC may exist yet: the rights database is readable
       by anyone (PHASE2.md), so these checks never depend on the caller's rights. */
    desc(&d, n->username, (unsigned short) strlen(n->username));
    if (sys$asctoid(&d, &id, &attrib) & 1) {
        set_cond(e, SS$_DUPIDENT);
        snprintf(e->text, sizeof e->text, "%%SYSTEM-F-DUPIDENT, the identifier %s already exists", n->username);
        return -1;
    }
    desc(&d, name, sizeof name - 1);
    st = sys$idtoasc(n->uic, &nlen, &d, &resid, &attrib, &ctx);
    sys$finish_rdb(&ctx);
    if (st & 1) {
        name[nlen] = '\0';
        set_cond(e, SS$_DUPIDENT);
        snprintf(e->text, sizeof e->text, "the UIC is already in use, by %s", name);
        return -1;
    }

    st = uaf_open(&fab, &rab, &rec);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    rab.rab$b_rac = RAB$C_KEY; rab.rab$b_krf = 0; rab.rab$l_kbf = key; rab.rab$b_ksz = 32;
    rab.rab$l_rop = RAB$M_NLK | RAB$M_RRL;
    uaf_key(key, n->username);
    st = sys$get(&rab);
    if (st & 1) { sys$close(&fab); set_cond(e, RMS$_DUP); e->kind = ST_E_CONFLICT; return -1; }
    uaf_key(key, n->template_user);
    st = sys$get(&rab);
    if (!(st & 1)) { sys$close(&fab); set_cond(e, st); return -1; }
    if (plen < rec.uaf$b_pwd_length || plen > 64) {      /* the template's minimum, before writing */
        sys$close(&fab);
        set_cond(e, SS$_INVPWDLEN);
        snprintf(e->text, sizeof e->text, "%%SYSTEM-F-INVPWDLEN, the password must be %u to 64 characters",
                 (unsigned) rec.uaf$b_pwd_length);
        return -1;
    }
    /* The template's record, with a new name (the tag byte kept), UIC and no history. */
    memset(rec.uaf$t_username, ' ', 31);
    memcpy(rec.uaf$t_username, n->username, strlen(n->username));
    rec.uaf$l_uic = n->uic;
    rec.uaf$q_pwd = 0;
    rec.uaf$q_pwd2 = 0;
    rec.uaf$w_logfails = 0;
    rec.uaf$w_salt = 0;
    rec.uaf$q_pwd_date = 0;
    rec.uaf$q_pwd2_date = 0;
    rec.uaf$q_lastlogin_i = 0;
    rec.uaf$q_lastlogin_n = 0;
    rab.rab$b_rac = RAB$C_KEY;
    rab.rab$l_rop = 0;
    rab.rab$l_rbf = (char *) &rec;
    /* rab$w_rsz is still the template's length, from its $GET */
    st = sys$put(&rab);
    sys$close(&fab);
    if (!(st & 1)) { set_cond(e, st); if (st == RMS$_DUP) e->kind = ST_E_CONFLICT; return -1; }

    if (st_plat_user_set_password(n->username, n->password, n->pre_expired, e)) {
        create_undo(n->username, n->uic, 0);
        return -1;
    }
    desc(&d, n->username, (unsigned short) strlen(n->username));
    st = sys$add_ident(&d, n->uic, 0, &id);          /* the UIC identifier, as AUTHORIZE ADD */
    if (!(st & 1)) { set_cond(e, st); create_undo(n->username, n->uic, 0); return -1; }
    if (n->more.fields && st_plat_user_modify(n->username, &n->more, e)) {
        create_undo(n->username, n->uic, 1);
        return -1;
    }
    if (n->copy_identifiers) {                       /* AUTHORIZE COPY does not; an option here */
        unsigned int tuic = 0, holder[2], th[2], hid, hattr, hctx = 0;
        st_ile3 it[2];
        desc(&d, n->template_user, (unsigned short) strlen(n->template_user));
        item(&it[0], UAI$_UIC, &tuic, 4, 0);
        item_end(&it[1]);
        if (sys$getuai(0, 0, &d, it, 0, 0, 0) & 1) {
            th[0] = tuic; th[1] = 0;
            holder[0] = n->uic; holder[1] = 0;
            while (sys$find_held((void *) th, &hid, &hattr, &hctx) & 1) {
                st = sys$add_holder(hid, (void *) holder, hattr);
                if (!(st & 1)) {
                    sys$finish_rdb(&hctx);
                    set_cond(e, st);
                    st_plat_user_delete(n->username, NULL);   /* undo, holdings included */
                    return -1;
                }
            }
            sys$finish_rdb(&hctx);
        }
    }
    if (n->create_directory) {
        /* As a site would by hand after AUTHORIZE ADD: the default directory, owned by
           the user. A failure here leaves the user in place and says so. */
        char spec[100];
        struct dsc$descriptor_s ds;
        unsigned int owner = n->uic;
        unsigned short penable = 0xFFFF, pvalue = 0xFF00;   /* (S:RWED,O:RWED,G,W) */
        st_user u;
        st_err e2;
        if (st_plat_user_get(n->username, &u, &e2) == 0 && !*u.defdev) {
            /* DEFAULT has none ("[USER]"): a bare directory would be made on whatever
               disk the serving process happens to use (PHASE4.md). Refuse instead. */
            snprintf(n->warning, sizeof n->warning,
                     "no directory was created: the account has no default device");
        } else if (st_plat_user_get(n->username, &u, &e2) == 0) {
            snprintf(spec, sizeof spec, "%s%s", u.defdev, u.defdir);
            desc(&ds, spec, (unsigned short) strlen(spec));
            st = lib$create_dir(&ds, &owner, &penable, &pvalue, 0, 0);
            if (!(st & 1)) {
                char m[256];
                msgtext(st, m, sizeof m);
                snprintf(n->warning, sizeof n->warning, "the directory %s was not created: %s", spec, m);
            }
        }
    }
    return 0;
}

int st_plat_user_delete(const char *username, st_err *e)
{
    struct FAB fab;
    struct RAB rab;
    static UAF rec;
    char key[32];
    unsigned int st, uic = 0, holder[2], ctx = 0, held[128], nheld = 0, id, attrib, i;
    struct dsc$descriptor_s d;
    st_ile3 it[2];

    desc(&d, username, (unsigned short) strlen(username));
    item(&it[0], UAI$_UIC, &uic, 4, 0);
    item_end(&it[1]);
    st = sys$getuai(0, 0, &d, it, 0, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    /* Write access first, by locking the record: a caller who may not delete it
       changes nothing at all. */
    st = uaf_open(&fab, &rab, &rec);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    uaf_key(key, username);
    rab.rab$b_rac = RAB$C_KEY; rab.rab$b_krf = 0; rab.rab$l_kbf = key; rab.rab$b_ksz = 32;
    rab.rab$l_rop = 0;
    st = sys$find(&rab);
    if (!(st & 1)) { sys$close(&fab); set_cond(e, st); return -1; }
    /* Its holdings and its UIC identifier, as AUTHORIZE REMOVE (PHASE4.md). */
    holder[0] = uic; holder[1] = 0;
    while (nheld < 128 && (sys$find_held((void *) holder, &id, &attrib, &ctx) & 1)) held[nheld++] = id;
    sys$finish_rdb(&ctx);
    for (i = 0; i < nheld; i++) {
        st = sys$rem_holder(held[i], (void *) holder);
        if (!(st & 1)) { sys$close(&fab); set_cond(e, st); return -1; }
    }
    st = sys$rem_ident(uic);
    if (!(st & 1) && st != SS$_NOSUCHID) { sys$close(&fab); set_cond(e, st); return -1; }
    st = sys$delete(&rab);
    sys$close(&fab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

/* ================================================================ access history (D13)

   Every source is opened on demand as the viewer's persona: what OpenVMS will not let
   them read is reported for that source, and the others are still shown (PHASE6.md).

   - Accounting gives every finished process. An SSH connection is the server's NETWORK
     process under SSH$SSH, its remote full name the client's host name; the user's
     commands are subprocesses beneath it, and a session with a shell or SFTP is a
     NETWORK process under the user, with the client address as full name.
   - The live process list gives the same for what is still running.
   - OpenSSH writes one log per connection, named <node>_<client host>_<pid>.log, the
     pid being that SSH$SSH process: so the method, the user and the address join the
     connection exactly. The lines carry no time; the file's dates do.
   - The audit journal has the failures that never reach accounting ($ACM: SSH
     passwords and Steward's own sign-in) and the break-ins.
   - Steward's audit log has its own sign-ins, with the browser's address. */

#define AX_PROCS 6000      /* process records kept from accounting and the live list */
#define AX_SSH   256       /* SSH connection logs */
#define AX_FAILS 1000      /* failures held to merge the journal's with the SSH logs' */
#define AX_NEAR  15        /* seconds: the same event seen by two sources */

typedef struct {
    long long    start, end;          /* end 0: still running */
    unsigned int pid, owner, status;
    unsigned char logfail, sub, live, taken;
    int          session;             /* an SSH connection's session process: index + 1 */
    char         user[13], term[16], node[16], rid[33], full[64], queue[32];
} ax_proc;

typedef struct {
    long long    start, end;
    unsigned int pid;
    int          accepted, joined;
    char         host[64], user[33], ip[48], method[48];
} ax_ssh;

typedef struct {
    long long start;
    int       source, kind, taken;
    char      user[33], route[24], from[64], term[24], detail[128];
} ax_fail;

static ax_proc   ax_p[AX_PROCS];
static ax_ssh    ax_s[AX_SSH];
static ax_fail   ax_f[AX_FAILS];
static int       ax_np, ax_ns, ax_nf;
static long long ax_off;              /* local_offset(), once per request */

static long long ax_time(unsigned long long v)
{
    if (v == 0 || v == ~0ull || v < VMS_EPOCH_OFFSET) return 0;
    return (long long) ((v - VMS_EPOCH_OFFSET) / 10000000ull) - ax_off;
}

/* Printable ASCII only, blanks trimmed: these strings come from files. */
static void ax_text(const unsigned char *p, size_t n, char *out, size_t outlen)
{
    size_t i, o = 0;
    for (i = 0; i < n && o + 1 < outlen; i++) out[o++] = (p[i] >= 32 && p[i] < 127) ? (char) p[i] : '?';
    while (o && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

static void ax_ascic(const unsigned char *pkt, unsigned plen, unsigned off, char *out, size_t outlen)
{
    out[0] = '\0';
    if (!off || off >= plen || off + 1u + pkt[off] > plen) return;
    ax_text(pkt + off + 1, pkt[off], out, outlen);
}

/* A terminal name. For a pseudo-terminal, accounting stores the unit number in binary
   after the device letters: "FTA" 45 02 is FTA581: (seen 2026-10-11, an SSH password
   failure). */
static void ax_terminal(const unsigned char *pkt, unsigned plen, unsigned off, char *out, size_t outlen)
{
    const unsigned char *t = pkt + off + 1;
    out[0] = '\0';
    if (!off || off >= plen || off + 1u + pkt[off] > plen) return;
    if (pkt[off] == 5 && t[0] >= 'A' && t[0] <= 'Z' && t[1] >= 'A' && t[1] <= 'Z' && t[2] >= 'A' && t[2] <= 'Z'
        && !(t[3] >= '0' && t[3] <= '9' && t[4] >= '0' && t[4] <= '9'))
        snprintf(out, outlen, "%.3s%u:", (const char *) t, (unsigned) (t[3] | t[4] << 8));
    else ax_text(t, pkt[off], out, outlen);
}

/* The remote full name is word-counted (PHASE6.md: found in a raw dump). */
static void ax_asciw(const unsigned char *pkt, unsigned plen, unsigned off, char *out, size_t outlen)
{
    unsigned n;
    out[0] = '\0';
    if (!off || off + 2 > plen) return;
    n = pkt[off] | pkt[off + 1] << 8;
    if (off + 2 + n > plen) return;
    ax_text(pkt + off + 2, n, out, outlen);
}

static void ax_upper(char *s)
{
    for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s = (char) (*s - 32);
}

static int ax_prefix(const char *s, const char *p) { return !strncmp(s, p, strlen(p)); }

static int ax_ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x = (char) (x - 32);
        if (y >= 'a' && y <= 'z') y = (char) (y - 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

static long long ax_abs(long long v) { return v < 0 ? -v : v; }

/* Room for one more process record. When full, the earliest written gives way, in
   turn: accounting is in time order, so that is the oldest. (A scan for the oldest
   on every insert made a busy file quadratic: security review, Phase 5.) */
static int ax_ring;

static ax_proc *ax_new_proc(void)
{
    ax_proc *p;
    if (ax_np < AX_PROCS) p = &ax_p[ax_np++];
    else { p = &ax_p[ax_ring]; ax_ring = (ax_ring + 1) % AX_PROCS; }
    memset(p, 0, sizeof *p);
    return p;
}

/* The next record, skipping any longer than the buffer (RMS-W-RTB) rather than
   giving up on the whole file: one odd record must not hide the rest. */
static unsigned int ax_get(struct RAB *rab)
{
    unsigned int st;
    while ((st = sys$get(rab)) == RMS$_RTB) ;
    return st;
}

/* End a wildcard search early, releasing RMS's directory context. */
static void ax_search_end(struct FAB *fab, struct NAM *nam)
{
    nam->nam$b_nop |= NAM$M_SYNCHK;
    fab->fab$b_fns = 0;
    sys$parse(fab);
}

static void ax_cond(unsigned int *cond, char *text, unsigned int st)
{
    *cond = st;
    msgtext(st, text, 96);
}

/* Open a file to read, shared with whoever is writing it, optionally with its dates. */
static unsigned int ax_open(struct FAB *fab, struct RAB *rab, struct XABDAT *dat,
                            const char *name, const char *dflt, unsigned char *buf, unsigned short size)
{
    unsigned int st;
    *fab = cc$rms_fab;
    *rab = cc$rms_rab;
    fab->fab$l_fna = (char *) name;
    fab->fab$b_fns = (unsigned char) strlen(name);
    if (dflt) { fab->fab$l_dna = (char *) dflt; fab->fab$b_dns = (unsigned char) strlen(dflt); }
    fab->fab$b_fac = FAB$M_GET;
    fab->fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_UPI;
    if (dat) { *dat = cc$rms_xabdat; fab->fab$l_xab = (void *) dat; }
    st = sys$open(fab);
    if (!(st & 1)) return st;
    rab->rab$l_fab = fab;
    rab->rab$l_ubf = (char *) buf;
    rab->rab$w_usz = size;
    rab->rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    st = sys$connect(rab);
    if (!(st & 1)) sys$close(fab);
    return st;
}

/* ---- accounting: finished processes and LOGINOUT's failures ---- */

static unsigned int ax_accounting(long long since, long long until)
{
    static unsigned char rec[65535];
    struct FAB fab;
    struct RAB rab;
    unsigned int st = ax_open(&fab, &rab, 0, "ACCOUNTNG", "SYS$MANAGER:.DAT", rec, sizeof rec);
    if (!(st & 1)) return st;
    while ((st = ax_get(&rab)) & 1) {
        unsigned rlen = rab.rab$w_rsz, w = rec[0] | rec[1] << 8, type = (w >> 1) & 0x7F, sub = (w >> 8) & 0xF;
        unsigned long long systime = 0, login = 0;
        unsigned off = ACR$K_HDRLEN;
        long long start, end;
        ax_proc *p, tmp;
        int i;
        if (rlen < ACR$K_HDRLEN || (w & 1)) continue;
        if (type != ACR$K_PRCDEL && type != ACR$K_LOGFAIL) continue;
        if (type == ACR$K_PRCDEL && sub == ACR$K_DETACHED) continue;
        for (i = 0; i < 8; i++) systime |= (unsigned long long) rec[4 + i] << (8 * i);
        memset(&tmp, 0, sizeof tmp);
        while (off + 4 <= rlen) {
            const unsigned char *k = rec + off;
            unsigned pw = k[0] | k[1] << 8, plen = k[2] | k[3] << 8, ptype = (pw >> 1) & 0x7F;
            if (plen < 4 || off + plen > rlen) break;
            if (ptype == ACR$K_ID && plen >= sizeof(struct acrdef2)) {
                struct acrdef2 id;     /* the __OLD_STARLET names: this file is built without __NEW_STARLET */
                memcpy(&id, k, sizeof id);        /* packets need not be aligned */
                tmp.pid = id.acr$l_pid;
                tmp.owner = id.acr$l_owner;
                ax_ascic(k, plen, id.acr$w_username, tmp.user, sizeof tmp.user);
                ax_terminal(k, plen, id.acr$w_terminal, tmp.term, sizeof tmp.term);
                ax_ascic(k, plen, id.acr$w_nodename, tmp.node, sizeof tmp.node);
                ax_ascic(k, plen, id.acr$w_remoteid, tmp.rid, sizeof tmp.rid);
                ax_ascic(k, plen, id.acr$w_queue, tmp.queue, sizeof tmp.queue);
                if (id.acr$v_fullname) ax_asciw(k, plen, id.acr$w_fullname, tmp.full, sizeof tmp.full);
            } else if (ptype == ACR$K_RESOURCE && plen >= sizeof(struct acrdef3)) {
                struct acrdef3 r;
                memcpy(&r, k, sizeof r);
                memcpy(&login, &r.acr$q_login, 8);
                tmp.status = r.acr$l_status;
            }
            off += plen;
        }
        end = ax_time(systime);
        start = type == ACR$K_LOGFAIL ? end : ax_time(login);
        if (!start) start = end;
        if (end < since - AX_NEAR || start > until) continue;
        p = ax_new_proc();
        *p = tmp;
        p->start = start;
        p->end = type == ACR$K_LOGFAIL ? 0 : end;
        p->logfail = type == ACR$K_LOGFAIL;
        p->sub = (unsigned char) sub;
    }
    sys$close(&fab);
    return st == RMS$_EOF ? SS$_NORMAL : st;
}

/* ---- the live process list ---- */

/* A TELNET or LAT terminal knows its far end: "Host: 192.0.2.7 Port: 51022". */
static void ax_accpor(const char *term, char *out, size_t outlen)
{
    char buf[128] = { 0 }, *h;
    unsigned short len = 0;
    unsigned int iosb[2];
    struct dsc$descriptor_s d;
    st_ile3 it[2];
    out[0] = '\0';
    if (!*term) return;
    desc(&d, term, (unsigned short) strlen(term));
    item(&it[0], DVI$_TT_ACCPORNAM, buf, sizeof buf - 1, &len);
    item_end(&it[1]);
    if (!(sys$getdviw(0, 0, &d, it, (void *) iosb, 0, 0, 0) & 1) || !(iosb[0] & 1)) return;
    buf[len] = '\0';
    h = strstr(buf, "Host: ");
    if (h) {
        size_t n;
        h += 6;
        for (n = 0; h[n] && h[n] != ' ' && n + 1 < outlen; n++) out[n] = h[n];
        out[n] = '\0';
    } else ax_text((unsigned char *) buf, len, out, outlen);
}

static void ax_live(void)
{
    unsigned int ctx = 0xFFFFFFFFu, pid, owner, mode, iosb[2], st, login[2], self = 0;
    char user[13], term[16];
    unsigned short l[6];
    st_ile3 it[7];
    item(&it[0], JPI$_PID, &pid, 4, &l[0]);
    item(&it[1], JPI$_OWNER, &owner, 4, &l[1]);
    item(&it[2], JPI$_MODE, &mode, 4, &l[2]);
    item(&it[3], JPI$_USERNAME, user, 12, &l[3]);
    item(&it[4], JPI$_TERMINAL, term, sizeof term - 1, &l[4]);
    item(&it[5], JPI$_LOGINTIM, login, 8, &l[5]);
    item_end(&it[6]);
    if (sys$getjpiw(0, 0, 0, it, iosb, 0, 0) & 1) self = pid;   /* not this process */
    for (;;) {
        ax_proc *p;
        pid = owner = mode = 0;
        login[0] = login[1] = 0;
        l[3] = l[4] = 0;
        st = sys$getjpiw(0, &ctx, 0, it, iosb, 0, 0);
        if (st & 1) st = iosb[0] & 0xFFFF;
        if (st == SS$_NOMOREPROC) break;
        if (st == SS$_NOPRIV || st == SS$_SUSPENDED) continue;   /* not the viewer's to see */
        if (!(st & 1)) break;
        if (pid == self) continue;
        if (owner == 0 && mode != JPI$K_INTERACTIVE && mode != JPI$K_NETWORK && mode != JPI$K_BATCH) continue;
        p = ax_new_proc();
        p->pid = pid;
        p->owner = owner;
        p->live = 1;
        p->start = ax_time(((unsigned long long) login[1] << 32) | login[0]);
        p->sub = (unsigned char) (owner ? ACR$K_SUBPROCESS : mode == JPI$K_INTERACTIVE ? ACR$K_INTERACTIVE
                                  : mode == JPI$K_NETWORK ? ACR$K_NETWORK : ACR$K_BATCH);
        blank_trim(user, l[3], p->user, sizeof p->user);
        ax_text((unsigned char *) term, l[4], p->term, sizeof p->term);
        if (p->sub == ACR$K_INTERACTIVE) ax_accpor(p->term, p->full, sizeof p->full);
    }
}

/* ---- OpenSSH's per-connection logs ---- */

static void ax_add_fail(long long t, int source, int kind, const char *user, const char *route,
                        const char *from, const char *term, const char *detail)
{
    ax_fail *f;
    if (ax_nf == AX_FAILS) return;
    f = &ax_f[ax_nf++];
    memset(f, 0, sizeof *f);
    f->start = t;
    f->source = source;
    f->kind = kind;
    st_copy(f->user, sizeof f->user, user);
    st_copy(f->route, sizeof f->route, route);
    st_copy(f->from, sizeof f->from, from);
    st_copy(f->term, sizeof f->term, term);
    st_copy(f->detail, sizeof f->detail, detail);
}

/* The word after "key " in line, into out. */
static int ax_word_after(const char *line, const char *key, char *out, size_t outlen)
{
    const char *s = strstr(line, key);
    size_t n;
    if (!s) return 0;
    s += strlen(key);
    for (n = 0; s[n] && s[n] != ' ' && n + 1 < outlen; n++) out[n] = s[n];
    out[n] = '\0';
    return n > 0;
}

static void ax_ssh_line(ax_ssh *c, const char *line)
{
    char user[33], ip[48], method[24], key[24];
    if (!strncmp(line, "Accepted ", 9) && ax_word_after(line, "Accepted ", method, sizeof method)
        && ax_word_after(line, " for ", user, sizeof user) && ax_word_after(line, " from ", ip, sizeof ip)) {
        c->accepted = 1;
        st_copy(c->user, sizeof c->user, user);
        ax_upper(c->user);
        st_copy(c->ip, sizeof c->ip, ip);
        if (ax_word_after(line, "ssh2: ", key, sizeof key)) snprintf(c->method, sizeof c->method, "%s %s", method, key);
        else st_copy(c->method, sizeof c->method, method);
    } else if (!strncmp(line, "Failed ", 7) && ax_word_after(line, "Failed ", method, sizeof method)
               && ax_word_after(line, " from ", ip, sizeof ip)
               && (ax_word_after(line, " invalid user ", user, sizeof user) || ax_word_after(line, " for ", user, sizeof user))) {
        char d[128];
        ax_upper(user);
        snprintf(d, sizeof d, "%s refused%s", method, strstr(line, " invalid user ") ? ": no such user" : "");
        ax_add_fail(c->start, ST_SRC_SSH, ST_AE_FAILURE, user, "SSH", ip, "", d);
    } else if (!strncmp(line, "Invalid user ", 13) && ax_word_after(line, "Invalid user ", user, sizeof user)
               && ax_word_after(line, " from ", ip, sizeof ip)) {
        int i;
        ax_upper(user);
        for (i = 0; i < ax_nf; i++)    /* "Failed ... for invalid user" says it already */
            if (ax_f[i].source == ST_SRC_SSH && ax_f[i].start == c->start && !strcmp(ax_f[i].user, user)) break;
        if (i == ax_nf) ax_add_fail(c->start, ST_SRC_SSH, ST_AE_FAILURE, user, "SSH", ip, "", "no such user");
    }
}

static unsigned int ax_ssh_logs(long long since, long long until)
{
    static const char spec[] = "SSH$ROOT:[VAR]*_*.LOG;*";
    static unsigned char line[1024];
    char esa[256], rsa[256];
    struct FAB fab = cc$rms_fab;
    struct NAM nam = cc$rms_nam;
    unsigned int st;
    fab.fab$l_fna = (char *) spec;
    fab.fab$b_fns = (unsigned char) (sizeof spec - 1);
    fab.fab$l_nam = &nam;
    nam.nam$l_esa = esa; nam.nam$b_ess = sizeof esa - 1;
    nam.nam$l_rsa = rsa; nam.nam$b_rss = sizeof rsa - 1;
    st = sys$parse(&fab);
    if (!(st & 1)) return st;
    while (ax_ns < AX_SSH && ((st = sys$search(&fab)) & 1)) {
        char name[128], *u1, *u2, *end;
        struct FAB f;
        struct RAB r;
        struct XABDAT dat;
        unsigned long pid;
        ax_ssh *c;
        int lines = 0;
        size_t nl = nam.nam$b_name < sizeof name ? nam.nam$b_name : sizeof name - 1;
        memcpy(name, nam.nam$l_name, nl);
        name[nl] = '\0';
        /* <node>_<client host>_<pid>: the pid is 8 hex digits; anything else (the
           server's own SSH$SSHD_STARTUP.LOG) is not a connection. */
        u1 = strchr(name, '_');
        u2 = strrchr(name, '_');
        if (!u1 || u2 == u1 || strlen(u2 + 1) != 8) continue;
        pid = strtoul(u2 + 1, &end, 16);
        if (*end) continue;
        rsa[nam.nam$b_rsl] = '\0';
        st = ax_open(&f, &r, &dat, rsa, 0, line, sizeof line - 1);
        if (!(st & 1)) {
            if (st == RMS$_PRV) { ax_search_end(&fab, &nam); return st; }   /* the viewer may not read these */
            continue;                           /* purged under us, or busy */
        }
        c = &ax_s[ax_ns];
        memset(c, 0, sizeof *c);
        c->pid = (unsigned int) pid;
        {
            unsigned long long q;
            memcpy(&q, &dat.xab$q_cdt, 8);
            c->start = ax_time(q);
            memcpy(&q, &dat.xab$q_rdt, 8);
            c->end = ax_time(q);
        }
        if (c->end < c->start) c->end = c->start;
        ax_text((unsigned char *) u1 + 1, (size_t) (u2 - u1 - 1), c->host, sizeof c->host);
        if (c->end >= since - AX_NEAR && c->start <= until) {
            ax_ns++;
            while (lines++ < 400 && (ax_get(&r) & 1)) {
                line[r.rab$w_rsz] = '\0';
                ax_ssh_line(c, (char *) line);
            }
        }
        sys$close(&f);
    }
    if (st & 1) ax_search_end(&fab, &nam);   /* stopped at AX_SSH, not at the end */
    return (st == RMS$_NMF || st == RMS$_FNF || (st & 1)) ? SS$_NORMAL : st;
}

/* ---- the security audit journal: failures and break-ins ---- */

static void ax_term_route(const char *term, char *route, size_t rlen, char *detail, size_t dlen)
{
    const char *r = "local", *d = "";
    if (ax_prefix(term, "OPA")) d = "console";
    else if (ax_prefix(term, "TNA")) r = "TELNET";
    else if (ax_prefix(term, "RTA")) r = "DECnet";
    else if (ax_prefix(term, "LTA")) r = "LAT";
    st_copy(route, rlen, r);
    if (detail) st_copy(detail, dlen, d);
}

static unsigned int ax_journal(long long since, long long until)
{
    static unsigned char rec[65535];
    struct FAB fab;
    struct RAB rab;
    unsigned int st = ax_open(&fab, &rab, 0, "SYS$MANAGER:SECURITY.AUDIT$JOURNAL", 0, rec, sizeof rec);
    if (!(st & 1)) return st;
    while ((st = ax_get(&rab)) & 1) {
        unsigned rlen = rab.rab$w_rsz, type = rec[0] | rec[1] << 8, sub = rec[2] | rec[3] << 8;
        unsigned npk = rec[6] | rec[7] << 8, off = NSA$C_MSG_HDR_LENGTH, k, status = 0;
        char user[33] = "", term[24] = "", rnode[64] = "", ruser[33] = "", rfull[64] = "";
        char route[24], detail[128], msg[96];
        long long t = 0;
        if (type != NSA$C_MSG_LOGFAIL && type != NSA$C_MSG_BREAKIN) continue;
        for (k = 0; k < npk && off + 4 <= rlen; k++) {     /* a packet's size includes its header */
            unsigned psize = rec[off] | rec[off + 1] << 8, ptype = rec[off + 2] | rec[off + 3] << 8;
            const unsigned char *d = rec + off + 4;
            if (psize < 4 || off + psize > rlen) break;
            switch (ptype) {
            case NSA$C_PKT_TIME_STAMP:
                if (psize >= 12) {
                    unsigned long long q = 0;
                    int i;
                    for (i = 7; i >= 0; i--) q = (q << 8) | d[i];
                    t = ax_time(q);
                }
                break;
            case NSA$C_PKT_USERNAME: ax_text(d, psize - 4, user, sizeof user); break;
            case NSA$C_PKT_TERMINAL: ax_text(d, psize - 4, term, sizeof term); break;
            case NSA$C_PKT_REMOTE_NODENAME: ax_text(d, psize - 4, rnode, sizeof rnode); break;
            case NSA$C_PKT_REMOTE_USERNAME: ax_text(d, psize - 4, ruser, sizeof ruser); break;
            case NSA$C_PKT_REMOTE_NODE_FULLNAME: ax_text(d, psize - 4, rfull, sizeof rfull); break;
            case NSA$C_PKT_FINAL_STATUS: if (psize >= 8) memcpy(&status, d, 4); break;
            }
            off += psize;
        }
        if (t < since || t > until) continue;
        /* Steward's own sign-ins name it as the remote user; its log has them, with
           the browser's real address rather than the proxy's. */
        if (type == NSA$C_MSG_LOGFAIL && !strcmp(ruser, "STEWARD")) continue;
        msg[0] = '\0';
        if (status) msgtext(status, msg, sizeof msg);
        if (sub == NSA$C_NETWORK) st_copy(route, sizeof route, "network");
        else if (sub == NSA$C_BATCH) st_copy(route, sizeof route, "batch");
        else ax_term_route(term, route, sizeof route, 0, 0);
        if (type == NSA$C_MSG_BREAKIN) snprintf(detail, sizeof detail, "break-in%s%s", *msg ? ": " : "", msg);
        else st_copy(detail, sizeof detail, msg);
        ax_add_fail(t, ST_SRC_AUDIT, type == NSA$C_MSG_BREAKIN ? ST_AE_BREAKIN : ST_AE_FAILURE, user, route,
                    *rnode ? rnode : rfull, term, detail);
    }
    sys$close(&fab);
    return st == RMS$_EOF ? SS$_NORMAL : st;
}

/* ---- Steward's own audit log ---- */

/* Days since 1970-01-01 of a civil date (H. Hinnant's algorithm). */
static long long ax_days(int y, int m, int d)
{
    long long era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* A value from one of our own records: key="..." with \" \\ \xNN escapes (st_app.c). */
static void ax_kv(const char *line, const char *key, char *out, size_t outlen)
{
    char pat[24];
    const char *s;
    size_t o = 0;
    snprintf(pat, sizeof pat, " %s=\"", key);
    out[0] = '\0';
    if (!(s = strstr(line, pat))) return;
    for (s += strlen(pat); *s && *s != '"' && o + 1 < outlen; s++) {
        if (*s == '\\' && s[1] == 'x' && s[2] && s[3]) { out[o++] = '?'; s += 3; }
        else if (*s == '\\' && s[1]) out[o++] = *++s;
        else out[o++] = *s;
    }
    out[o] = '\0';
}

typedef struct { long long start; char user[33], from[64]; } ax_open_session;

static int ax_emit_steward(const ax_open_session *o, long long end, long long since, long long until,
                           st_access_cb fn, void *ctx)
{
    st_access_event a;
    if ((end ? end : until) < since || o->start > until) return 0;
    memset(&a, 0, sizeof a);
    a.start = o->start;
    a.end = end;
    a.kind = ST_AE_SESSION;
    a.source = ST_SRC_STEWARD;
    st_copy(a.user, sizeof a.user, o->user);
    st_copy(a.route, sizeof a.route, "Steward");
    st_copy(a.from, sizeof a.from, o->from);
    st_copy(a.detail, sizeof a.detail, end ? "signed in" : "signed in; no sign-out recorded");
    return fn(&a, ctx);
}

static unsigned int ax_steward(long long since, long long until, st_access_cb fn, void *ctx, int *stop)
{
    static unsigned char line[1100];
    static ax_open_session open_[64];
    struct FAB fab;
    struct RAB rab;
    int nopen = 0, i;
    unsigned int st;
    if (!*steward_log) return SS$_NORMAL;
    st = ax_open(&fab, &rab, 0, steward_log, 0, line, sizeof line - 1);
    if (!(st & 1)) return st;
    while (!*stop && ((st = ax_get(&rab)) & 1)) {
        char user[33], from[64], action[24], outcome[16], detail[96];
        int y, mo, d, h, mi, s;
        long long t;
        line[rab.rab$w_rsz] = '\0';
        if (sscanf((char *) line, "%4d-%2d-%2dT%2d:%2d:%2dZ AUDIT ", &y, &mo, &d, &h, &mi, &s) != 6) continue;
        t = ax_days(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
        ax_kv((char *) line, "action", action, sizeof action);
        if (strcmp(action, "login") && strcmp(action, "logout") && strcmp(action, "session-expired")) continue;
        ax_kv((char *) line, "user", user, sizeof user);     /* " AUDIT user=": a blank before it too */
        ax_kv((char *) line, "client", from, sizeof from);
        ax_kv((char *) line, "outcome", outcome, sizeof outcome);
        ax_kv((char *) line, "detail", detail, sizeof detail);
        ax_upper(user);
        for (i = 0; i < nopen && !(!strcmp(open_[i].user, user) && !strcmp(open_[i].from, from)); i++) ;
        if (!strcmp(action, "login") && strcmp(outcome, "ok")) {
            if (t >= since)
                ax_add_fail(t, ST_SRC_STEWARD, ST_AE_FAILURE, user, "Steward", from, "",
                            *detail ? detail : !strcmp(outcome, "expired") ? "password expired" : "refused");
            continue;
        }
        if (i < nopen) {              /* a sign-out, or a new sign-in replacing an open one */
            if (ax_emit_steward(&open_[i], strcmp(action, "login") ? t : 0, since, until, fn, ctx)) *stop = 1;
            open_[i] = open_[--nopen];
        }
        if (!strcmp(action, "login") && t <= until) {
            if (nopen == 64) {        /* the oldest gives way, unended */
                if (ax_emit_steward(&open_[0], 0, since, until, fn, ctx)) *stop = 1;
                open_[0] = open_[--nopen];
            }
            open_[nopen].start = t;
            st_copy(open_[nopen].user, sizeof open_[0].user, user);
            st_copy(open_[nopen].from, sizeof open_[0].from, from);
            nopen++;
        }
    }
    for (i = 0; i < nopen && !*stop; i++)
        if (ax_emit_steward(&open_[i], 0, since, until, fn, ctx)) *stop = 1;
    sys$close(&fab);
    return (st & 1) || st == RMS$_EOF ? SS$_NORMAL : st;
}

/* ---- joining and reporting ---- */

static int ax_emit(const ax_proc *p, int kind, int source, const char *user, const char *route,
                   const char *from, const char *detail, st_access_cb fn, void *ctx)
{
    st_access_event a;
    memset(&a, 0, sizeof a);
    a.start = p->start;
    a.end = p->live ? 0 : p->end;
    a.kind = kind;
    a.source = source;
    a.pid = p->pid;
    st_copy(a.user, sizeof a.user, user);
    st_copy(a.route, sizeof a.route, route);
    st_copy(a.from, sizeof a.from, from);
    st_copy(a.terminal, sizeof a.terminal, p->term);
    st_copy(a.detail, sizeof a.detail, detail);
    return fn(&a, ctx);
}

/* Inside c's lifetime, give or take a moment: started after it and, if both have
   ended, ended before it. (Started-within alone let a connection that closed just
   as the next one opened claim that one's session.) */
static int ax_within(const ax_proc *p, const ax_proc *c)
{
    if (p->start + 2 < c->start) return 0;
    if (c->live || !c->end) return 1;
    return !p->live && p->end && p->end <= c->end + 2;
}

/* An SSH connection: its log, the user's session process and commands beneath it. */
/* Client host names and their addresses. Accounting names an SSH connection's client
   by host (the server's process) but a session by address (the user's process), so
   one client showed under two names; learnt from connections that have both. */
#define AX_HOSTS 64
static struct { char host[64], ip[48]; } ax_h[AX_HOSTS];
static int ax_nh;

static void ax_host_learn(const char *host, const char *ip)
{
    int i;
    if (!*host || !*ip || ax_ieq(host, ip)) return;
    for (i = 0; i < ax_nh; i++) if (ax_ieq(ax_h[i].host, host)) return;
    if (ax_nh == AX_HOSTS) return;
    st_copy(ax_h[ax_nh].host, sizeof ax_h[0].host, host);
    st_copy(ax_h[ax_nh].ip, sizeof ax_h[0].ip, ip);
    ax_nh++;
}

static const char *ax_host_ip(const char *host)
{
    int i;
    for (i = 0; i < ax_nh; i++) if (ax_ieq(ax_h[i].host, host)) return ax_h[i].ip;
    return 0;
}

static void ax_hosts(void)
{
    int i;
    ax_nh = 0;
    for (i = 0; i < ax_ns; i++) if (ax_s[i].accepted) ax_host_learn(ax_s[i].host, ax_s[i].ip);
    for (i = 0; i < ax_np; i++)
        if (ax_p[i].session) ax_host_learn(ax_p[i].full, ax_p[ax_p[i].session - 1].full);
}

static int ax_ssh_conn(ax_proc *c, st_access_cb fn, void *ctx)
{
    char user[33] = "", from[64], detail[128] = "", how[48] = "", host[64];
    ax_ssh *log = 0;
    int i, j, commands = 0;
    st_copy(from, sizeof from, c->full);
    for (i = 0; i < ax_ns; i++)
        if (ax_s[i].pid == c->pid && ax_abs(ax_s[i].start - c->start) <= 60) { log = &ax_s[i]; log->joined = 1; break; }
    if (log && !*from) st_copy(from, sizeof from, log->host);
    if (log && log->accepted) {
        st_copy(user, sizeof user, log->user);
        st_copy(from, sizeof from, log->ip);
        st_copy(how, sizeof how, log->method);
    }
    st_copy(host, sizeof host, log && !*c->full ? log->host : c->full);
    /* the commands: SSH$SSH's subprocess, and the user's beneath that */
    for (i = 0; i < ax_np && !*user; i++) {
        ax_proc *s = &ax_p[i];
        if (s->sub != ACR$K_SUBPROCESS || s->owner != c->pid || !ax_within(s, c)) continue;
        for (j = 0; j < ax_np; j++) {
            ax_proc *u = &ax_p[j];
            if (u->sub == ACR$K_SUBPROCESS && u->owner == s->pid && ax_within(u, s) && !ax_prefix(u->user, "SSH$")) {
                st_copy(user, sizeof user, u->user);
                ax_upper(user);
                commands = 1;
                break;
            }
        }
    }
    /* a shell or SFTP session: a NETWORK process under the user, with the address */
    if (c->session) {
        ax_proc *n = &ax_p[c->session - 1];
        if (!*user) { st_copy(user, sizeof user, n->user); ax_upper(user); }
        if (*n->full) st_copy(from, sizeof from, n->full);
    }
    if (!strcmp(from, host) && ax_host_ip(host)) st_copy(from, sizeof from, ax_host_ip(host));
    /* what it was, how it signed in, and the client's name when the address is shown */
    {
        const char *what = c->session ? "session" : commands ? "command" : "";
        size_t o = (size_t) snprintf(detail, sizeof detail, "%s%s%s", what, *what && *how ? ", " : "", how);
        if (*host && strcmp(from, host) && o < sizeof detail)
            snprintf(detail + o, sizeof detail - o, "%shost %s", o ? "; " : "", host);
    }
    if (!*user) {
        /* No user ever ran: a connection whose sign-in failed. The failure (journal or
           log) is the event; it was over SSH, which the journal alone cannot say. */
        int found = 0;
        for (i = 0; i < ax_nf; i++) {
            ax_fail *f = &ax_f[i];
            if ((f->source == ST_SRC_AUDIT || f->source == ST_SRC_SSH) && f->start + 2 >= c->start
                && (c->live || !c->end || f->start <= c->end + 2)) {
                st_copy(f->route, sizeof f->route, "SSH");
                found = 1;
            }
        }
        if (found) return 0;
        st_copy(detail, sizeof detail, log ? "no sign-in" : "no sign-in recorded");
    }
    return ax_emit(c, c->live ? ST_AE_CONNECTED : ST_AE_SESSION, c->live ? ST_SRC_LIVE : ST_SRC_ACCOUNTING,
                   user, "SSH", from, detail, fn, ctx);
}

/* Each session process to the SSH connection that holds it most closely: connections
   follow each other within the second, so the first that fits may be the one before. */
static void ax_ssh_sessions(void)
{
    int i, j;
    for (i = 0; i < ax_np; i++) {
        ax_proc *n = &ax_p[i];
        long long best = -1;
        int at = -1;
        if (n->logfail || n->sub != ACR$K_NETWORK || ax_prefix(n->user, "SSH$")) continue;
        for (j = 0; j < ax_np; j++) {
            ax_proc *c = &ax_p[j];
            long long slack;
            if (c->logfail || c->sub != ACR$K_NETWORK || !ax_prefix(c->user, "SSH$") || c->session || !ax_within(n, c)) continue;
            /* how far outside c it reaches: 0 when wholly inside */
            slack = (n->start < c->start ? c->start - n->start : 0)
                  + (!c->live && c->end && n->end > c->end ? n->end - c->end : 0);
            if (best < 0 || slack < best || (slack == best && c->start > ax_p[at].start)) { best = slack; at = j; }
        }
        if (at >= 0) { ax_p[at].session = i + 1; n->taken = 1; }
    }
}

static int ax_report(long long since, long long until, st_access_cb fn, void *ctx)
{
    int i, j;
    ax_ssh_sessions();
    ax_hosts();
    /* SSH connections first: they claim the user's processes beneath them. */
    for (i = 0; i < ax_np; i++) {
        ax_proc *c = &ax_p[i];
        if (c->logfail || c->sub != ACR$K_NETWORK || !ax_prefix(c->user, "SSH$")) continue;
        c->taken = 1;
        if ((c->live || c->end >= since) && c->start <= until && ax_ssh_conn(c, fn, ctx)) return 1;
    }
    for (i = 0; i < ax_np; i++) {
        ax_proc *p = &ax_p[i];
        char route[24], detail[128] = "", user[33];
        const char *from = *p->full ? p->full : p->rid;
        if (p->taken || p->sub == ACR$K_SUBPROCESS || p->sub == ACR$K_DETACHED) continue;
        if (!p->live && !p->logfail && p->end < since) continue;
        if (p->start > until || (p->logfail && p->start < since)) continue;
        /* a failure before a username was taken: LOGINOUT's "<login>", the name tried as remote ID */
        st_copy(user, sizeof user, p->user[0] == '<' && *p->rid ? p->rid : p->user);
        ax_upper(user);
        if (p->sub == ACR$K_BATCH) {
            st_copy(route, sizeof route, "batch");
            if (*p->queue) snprintf(detail, sizeof detail, "queue %s", p->queue);
            from = "";
        } else if (p->sub == ACR$K_NETWORK) {
            st_copy(route, sizeof route, "network");
            if (*p->node && *p->rid && !*p->full) {
                snprintf(detail, sizeof detail, "%s::%s", p->node, p->rid);
                from = p->node;
            }
        } else ax_term_route(p->term, route, sizeof route, detail, sizeof detail);
        if (p->logfail) {
            msgtext(p->status, detail, sizeof detail);
            ax_add_fail(p->start, ST_SRC_ACCOUNTING, ST_AE_FAILURE, user, route, from, p->term, detail);
            continue;
        }
        if (ax_emit(p, p->live ? ST_AE_CONNECTED : ST_AE_SESSION, p->live ? ST_SRC_LIVE : ST_SRC_ACCOUNTING,
                    user, route, from, detail, fn, ctx)) return 1;
    }
    /* SSH logs whose connection neither accounting nor the live list shows */
    for (i = 0; i < ax_ns; i++) {
        ax_ssh *s = &ax_s[i];
        st_access_event a;
        if (s->joined || !s->accepted || s->end < since || s->start > until) continue;
        memset(&a, 0, sizeof a);
        a.start = s->start;
        a.end = s->end;
        a.kind = ST_AE_SESSION;
        a.source = ST_SRC_SSH;
        a.pid = s->pid;
        st_copy(a.user, sizeof a.user, s->user);
        st_copy(a.route, sizeof a.route, "SSH");
        st_copy(a.from, sizeof a.from, s->ip);
        st_copy(a.detail, sizeof a.detail, s->method);
        if (fn(&a, ctx)) return 1;
    }
    /* Failures: the journal's, the SSH log's and LOGINOUT's accounting record of one
       attempt are one event, shown with the journal's time and status. */
    for (i = 0; i < ax_nf; i++) {
        ax_fail *f = &ax_f[i];
        if (f->source != ST_SRC_ACCOUNTING) continue;
        for (j = 0; j < ax_nf; j++) {
            ax_fail *g = &ax_f[j];
            if (g->source == ST_SRC_AUDIT && ax_ieq(g->user, f->user) && !strcmp(g->from, f->from)
                && ax_abs(g->start - f->start) <= AX_NEAR) { f->taken = 1; break; }
        }
    }
    for (i = 0; i < ax_nf; i++) {
        ax_fail *f = &ax_f[i];
        if (f->source != ST_SRC_SSH) continue;
        for (j = 0; j < ax_nf; j++) {
            ax_fail *g = &ax_f[j];
            if (g->source == ST_SRC_AUDIT && !g->taken && ax_ieq(g->user, f->user) && !strcmp(g->from, f->from)
                && ax_abs(g->start - f->start) <= AX_NEAR + 60) {
                g->taken = 1;          /* the journal's time and status; the route from SSH */
                st_copy(g->route, sizeof g->route, "SSH");
                f->taken = 1;
                break;
            }
        }
    }
    for (i = 0; i < ax_nf; i++) {
        ax_fail *f = &ax_f[i];
        st_access_event a;
        if (f->source != ST_SRC_AUDIT && f->taken) continue;
        if (f->start < since || f->start > until) continue;
        memset(&a, 0, sizeof a);
        a.start = f->start;
        a.kind = f->kind;
        a.source = f->source;
        st_copy(a.user, sizeof a.user, f->user);
        st_copy(a.route, sizeof a.route, f->route);
        st_copy(a.from, sizeof a.from, f->from);
        st_copy(a.terminal, sizeof a.terminal, f->term);
        st_copy(a.detail, sizeof a.detail, f->detail);
        if (fn(&a, ctx)) return 1;
    }
    return 0;
}

int st_plat_access(long long since, long long until, st_access_cb fn, void *ctx,
                   unsigned int src_cond[ST_SRC_COUNT], char src_text[ST_SRC_COUNT][96], st_err *e)
{
    unsigned int st;
    int i, stop = 0;
    (void) e;
    for (i = 0; i < ST_SRC_COUNT; i++) { src_cond[i] = 0; src_text[i][0] = '\0'; }
    ax_np = ax_ns = ax_nf = ax_ring = 0;
    ax_off = local_offset();
    if (!((st = ax_accounting(since, until)) & 1)) ax_cond(&src_cond[ST_SRC_ACCOUNTING], src_text[ST_SRC_ACCOUNTING], st);
    if (until >= st_plat_time() - 60) ax_live();
    if (!((st = ax_ssh_logs(since, until)) & 1)) ax_cond(&src_cond[ST_SRC_SSH], src_text[ST_SRC_SSH], st);
    if (!((st = ax_journal(since, until)) & 1)) ax_cond(&src_cond[ST_SRC_AUDIT], src_text[ST_SRC_AUDIT], st);
    if (!((st = ax_steward(since, until, fn, ctx, &stop)) & 1)) ax_cond(&src_cond[ST_SRC_STEWARD], src_text[ST_SRC_STEWARD], st);
    if (!stop) ax_report(since, until, fn, ctx);
    return 0;
}

/* ================================================================ logical names (D14)

   Listing: a short-lived detached process, created under the persona, runs the fixed
   procedure STEWARD_LNM.COM. It reads a table and a pattern (data, never commands)
   from a request mailbox, and SHOW LOGICAL/FULL writes the listing to a reply
   mailbox, then "%%END%% <status>". Its process name, STW<request>_<reply>, gives it
   the two mailbox units. Both mailboxes are the persona's, system and owner only.

   As found by probe (NOTES.md): LIB$SPAWN is refused under a persona; a subprocess
   waits for LIB$SPAWN's context; a mailbox as input makes LOGINOUT prompt; a mailbox
   as DCL's output gives RMS-F-DEV. Hence a detached process, a procedure file as its
   input and NLA0: as its output, and SHOW LOGICAL/OUTPUT= to the mailbox. */

#define LNM_REQ_MAXMSG 512
#define LNM_REP_MAXMSG 1024      /* reads never ask for more: MBTOOSML otherwise */
#define LNM_TIMEOUT_S  30

static unsigned int mbx_unit(unsigned short chan)
{
    unsigned int unit = 0, iosb[2];
    st_ile3 it[2];
    item(&it[0], DVI$_UNIT, &unit, 4, 0);
    item_end(&it[1]);
    sys$getdviw(0, chan, 0, it, (void *) iosb, 0, 0, 0);
    return unit;
}

int st_plat_lnm_list(const char *table, const char *pattern, const char *privs,
                     st_lnm_cb fn, void *ctx, st_err *e)
{
    static unsigned int efr, eft;   /* read and timer event flags, from LIB$GET_EF once */
    static char line[LNM_REP_MAXMSG + 1];
    unsigned short reqchan = 0, repchan = 0, iosb[4];
    unsigned int st, pid = 0, status = 0, delta[2], mask;
    char prc[16];
    struct dsc$descriptor_s img, in, nl, pn;
    st_lnm_parser p;
    int done = 0, timed_out = 0;

    if (!efr && (!(lib$get_ef(&efr) & 1) || !(lib$get_ef(&eft) & 1) || (efr / 32) != (eft / 32))) {
        efr = 0;
        set_text(e, ST_E_INTERNAL, "no event flags");
        return -1;
    }
    /* System and owner only (deny group and world). The owner is the persona. */
    st = sys$crembx(0, &reqchan, LNM_REQ_MAXMSG, 3 * LNM_REQ_MAXMSG, 0xFF00, 0, 0, 0, 0);
    if (st & 1) st = sys$crembx(0, &repchan, LNM_REP_MAXMSG, 16 * LNM_REP_MAXMSG, 0xFF00, 0, 0, 0, 0);
    if (!(st & 1)) goto fail;
    snprintf(prc, sizeof prc, "STW%u_%u", mbx_unit(reqchan), mbx_unit(repchan));
    st = sys$qiow(0, reqchan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0, (void *) table, strlen(table), 0, 0, 0, 0);
    if (st & 1) st = sys$qiow(0, reqchan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0, (void *) pattern, strlen(pattern), 0, 0, 0, 0);
    if (st & 1) st = sys$qiow(0, reqchan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0, (void *) privs, strlen(privs), 0, 0, 0, 0);
    if (!(st & 1)) goto fail;

    desc(&img, "SYS$SYSTEM:LOGINOUT.EXE", 23);
    desc(&in, lnm_helper, (unsigned short) strlen(lnm_helper));
    desc(&nl, "NLA0:", 5);
    desc(&pn, prc, (unsigned short) strlen(prc));
    st = sys$creprc(&pid, &img, &in, &nl, &nl, 0, 0, &pn, 4, 0, 0, PRC$M_DETACH, 0, 0);
    if (!(st & 1)) goto fail;

    /* The listing, line by line, until the procedure's last line or the deadline. */
    delta[0] = (unsigned int) (-(long long) LNM_TIMEOUT_S * 10000000LL);
    delta[1] = 0xFFFFFFFFu;
    sys$clref(eft);
    sys$setimr(eft, (void *) delta, 0, (unsigned long) &efr, 0);
    st_lnm_parse_init(&p, fn, ctx);
    mask = (1u << (efr % 32)) | (1u << (eft % 32));
    while (!done) {
        unsigned int rst;
        memset(iosb, 0, sizeof iosb);
        rst = sys$qio(efr, repchan, IO$_READVBLK, (void *) iosb, 0, 0, line, LNM_REP_MAXMSG, 0, 0, 0, 0);
        if (!(rst & 1)) { st = rst; break; }
        sys$wflor(efr, mask);
        if (!iosb[0]) {                      /* the timer, not the read */
            sys$cancel(repchan);
            sys$synch(efr, (void *) iosb);
            timed_out = 1;
            break;
        }
        /* RMS writes an end-of-file message when SHOW LOGICAL/OUTPUT= closes the
           mailbox, and again after the last line: the procedure's own last line, not
           these, ends the listing. */
        if (iosb[0] == SS$_ENDOFFILE) continue;
        if (!(iosb[0] & 1)) { st = iosb[0]; break; }
        line[iosb[1]] = '\0';
        if (!strncmp(line, "%%END%% ", 8)) {
            status = (unsigned int) strtoul(line + 8, NULL, 16);
            status &= 0x0FFFFFFFu;   /* without DCL's "message already shown" bit */
            /* SHOW LOGICAL returns IVLOGTAB as a warning (%X158), SSDEF has it fatal
               (%X15C): the same message. Compare without the severity. */
            if ((status & ~7u) == (SS$_IVLOGTAB & ~7u)) status = SS$_IVLOGTAB;
            done = 1;
            break;
        }
        st_lnm_parse_line(&p, line, iosb[1]);   /* once stopped, it only drains */
    }
    sys$cantim((unsigned long) &efr, 0);
    if (!done && pid) sys$delprc(&pid, 0, 0);   /* never leave one behind */
    sys$dassgn(reqchan);
    sys$dassgn(repchan);
    if (timed_out) { set_cond(e, SS$_TIMEOUT); return -1; }
    if (!done) { set_cond(e, st); return -1; }
    st_lnm_parse_end(&p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* SHOW LOGICAL's own failure */
    return 0;

fail:
    if (reqchan) sys$dassgn(reqchan);
    if (repchan) sys$dassgn(repchan);
    set_cond(e, st);
    return -1;
}

static void lnm_attrs(unsigned int a, int name, char *out, size_t outlen)
{
    out[0] = '\0';
    if (name) {
        if (a & LNM$M_NO_ALIAS) st_append(out, outlen, "no_alias,");
        if (a & LNM$M_CONFINE) st_append(out, outlen, "confine,");
        if (a & LNM$M_CRELOG) st_append(out, outlen, "crelog,");
        if (a & LNM$M_TABLE) st_append(out, outlen, "table,");
        if (a & LNM$M_CLUSTERWIDE) st_append(out, outlen, "clusterwide,");
    } else {
        if (a & LNM$M_CONCEALED) st_append(out, outlen, "concealed,");
        if (a & LNM$M_TERMINAL) st_append(out, outlen, "terminal,");
    }
    if (*out) out[strlen(out) - 1] = '\0';
}

int st_plat_lnm_get(const char *table, const char *name, st_lnm *out,
                    char table_out[ST_LNM_TABLE_MAX + 1], st_err *e)
{
    static const char *const modes[] = { "kernel", "exec", "super", "user" };
    struct dsc$descriptor_s tab, dir, nam;
    unsigned int attrs = 0, index = 0, maxidx = 0, st;
    unsigned char acmode = 0;
    unsigned short slen = 0, tlen = 0;
    char string[ST_LNM_NAME_MAX + 1], tname[ST_LNM_TABLE_MAX + 1];
    st_ile3 it[7];

    /* Only a real shareable table: one listed with the table attribute in
       LNM$SYSTEM_DIRECTORY. Not a search list of tables (which could name the
       process table, the service's own), not a process or job table of this process. */
    desc(&dir, "LNM$SYSTEM_DIRECTORY", 20);
    desc(&tab, table, (unsigned short) strlen(table));
    item(&it[0], LNM$_ATTRIBUTES, &attrs, 4, 0);
    item_end(&it[1]);
    st = sys$trnlnm(0, &dir, &tab, 0, it);
    if (st == SS$_NOLOGNAM || ((st & 1) && !(attrs & LNM$M_TABLE))) { set_cond(e, SS$_NOLOGTAB); return -1; }
    if (!(st & 1)) { set_cond(e, st); return -1; }

    memset(out, 0, sizeof *out);
    st_copy(out->name, sizeof out->name, name);
    desc(&nam, name, (unsigned short) strlen(name));
    for (index = 0; index <= maxidx && index < 128; index++) {
        memset(string, 0, sizeof string);
        attrs = 0;
        item(&it[0], LNM$_INDEX, &index, 4, 0);
        item(&it[1], LNM$_STRING, string, ST_LNM_NAME_MAX, &slen);
        item(&it[2], LNM$_ATTRIBUTES, &attrs, 4, 0);
        if (index == 0) {
            item(&it[3], LNM$_MAX_INDEX, &maxidx, 4, 0);
            item(&it[4], LNM$_ACMODE, &acmode, 1, 0);
            item(&it[5], LNM$_TABLE, tname, ST_LNM_TABLE_MAX, &tlen);
            item_end(&it[6]);
        } else item_end(&it[3]);
        st = sys$trnlnm(0, &tab, &nam, 0, it);
        if (st == SS$_NOLOGNAM) { set_cond(e, st); return 0; }
        if (!(st & 1)) { set_cond(e, st); return -1; }
        if (index == 0) {
            if (maxidx > 127) maxidx = 127;
            st_copy(out->mode, sizeof out->mode, acmode < 4 ? modes[acmode] : "?");
            lnm_attrs(attrs, 1, out->attributes, sizeof out->attributes);
            tname[tlen] = '\0';
            st_copy(table_out, ST_LNM_TABLE_MAX + 1, tname);
        }
        if (out->neq < ST_LNM_MAXEQ) {
            st_lnm_eq *q = &out->eq[out->neq++];
            string[slen] = '\0';
            st_copy(q->value, sizeof q->value, string);
            lnm_attrs(attrs, 0, q->attributes, sizeof q->attributes);
        } else out->more++;
    }
    return 1;
}

/* ================================================================ misc */

long long st_plat_time(void) { return (long long) time(NULL); }

void st_plat_audit(const char *line)
{
    char rec[1100];
    time_t t = time(NULL);
    size_t n;
    unsigned int st;
    n = strftime(rec, 32, "%Y-%m-%dT%H:%M:%SZ AUDIT ", gmtime(&t));
    strncpy(rec + n, line, sizeof rec - n - 1);
    rec[sizeof rec - 1] = '\0';
    if (!audit_open) { fprintf(stderr, "%s\n", rec); return; }
    arab.rab$l_rbf = rec;
    arab.rab$w_rsz = (unsigned short) strlen(rec);
    st = sys$put(&arab);
    if (st & 1) st = sys$flush(&arab);   /* on disk before the response goes out */
    if (!(st & 1)) {
        char m[256];
        msgtext(st, m, sizeof m);
        fprintf(stderr, "steward: audit write failed: %s\n%s\n", m, rec);
    }
}

void st_plat_log(const char *line)
{
    fprintf(stderr, "steward: %s\n", line);
}
