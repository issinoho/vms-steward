/* st_plat_vms.c - the platform on OpenVMS: system services, RMS, $ACM, personas.

   VSI C, 32-bit pointers (D3). Every finding this file relies on is in
   docs/PHASE0.md or docs/PHASE1.md, with the probe that established it:

   - $ACM, non-dialogue, authenticates; intrusion records name the client when
     ACME$_REMOTE_HOST_NAME and ACME$_REMOTE_USERNAME are given (probe_acm_host).
   - It accepts an expired password (probe_acm), so expiry is checked here, as the
     user: an unprivileged persona may $GETUAI its own record (probe_selfuai), so the
     service account needs no SYSPRV.
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
#include <lnmdef.h>
#include <prvdef.h>
#include <rms.h>
#include <rmsdef.h>
#include <ssdef.h>
#include <starlet.h>
#include <uaidef.h>
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
    case SS$_NOSUCHID: case RMS$_RNF:
        e->kind = ST_E_NOTFOUND; break;
    case SS$_IVIDENT: case SS$_BADPARAM:
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

int st_plat_init(const st_plat_config *cfg, st_err *e)
{
    unsigned int imp[2] = { PRV$M_DETACH, 0 }, st;   /* IMPERSONATE is the DETACH bit */

    /* The service account is authorized IMPERSONATE; make sure it is enabled. */
    st = sys$setprv(1, (void *) imp, 0, 0);
    if (st != SS$_NORMAL) { set_cond(e, st == SS$_NOTALLPRIV ? SS$_NOPRIV : st); return -1; }

    if (!cfg->session_file || !*cfg->session_file) {
        set_text(e, ST_E_INTERNAL, "STEWARD_SESSION_FILE is not defined");
        return -1;
    }
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
    st = sys$persona_create(&h, &d, 0, 0, 0);
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
