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
#include <sjcdef.h>         /* $SNDJBC (Phase 9b) */
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
#include <accdef.h>         /* the termination message (D14 helper) */
#include <msgdef.h>
#include <nsadef.h>         /* security audit journal records (Phase 6) */
#include <lib$routines.h>
#include <utcblkdef.h>   /* acmedef.h uses utcblk without including it (PHASE0) */
#include <acmedef.h>
#include "st_platform.h"
#include "st_proc.h"
#include "st_queue.h"
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
    case SS$_NOSYSNAM: case SS$_NOGRPNAM: case JBC$_NOPRIV:
        e->kind = ST_E_NOPRIV; break;
    case SS$_NOSUCHID: case RMS$_RNF: case SS$_NOLOGNAM: case SS$_NOLOGTAB: case SS$_IVLOGTAB:
    case SS$_NONEXPR: case JBC$_NOSUCHQUE: case JBC$_NOSUCHJOB: case JBC$_NOSUCHENT:
        e->kind = ST_E_NOTFOUND; break;
    case SS$_IVIDENT: case SS$_BADPARAM: case SS$_INVPWDLEN: case SS$_PWDINHIS:
    case SS$_PWDINDIC: case SS$_PWDWEAK: case SS$_PWDSYNTAX:
        e->kind = ST_E_INVALID; break;
    case SS$_DUPIDENT: case RMS$_DUP: case JBC$_EXECUTING:
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
static struct FAB   hfab;           /* the recording (D22) */
static struct RAB   hrab;
static struct XABKEY hxab;
static int          history_open;

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

/* The recording, [.RUN]MONITOR.DAT (D22): an indexed file of fixed records keyed by
   their first four bytes (st_mrec.h), created by whichever opens it first, recorder or
   pool. The recorder writes (one $PUT a minute, replacing the slot); the pool reads,
   regardless of the recorder's lock (NLK, RRL): a reading is replaced whole or not at
   all, and one from the previous lap is told apart by its time. */
static unsigned int open_history(const char *path, int writer)
{
    unsigned int st;
    hfab = cc$rms_fab;
    hxab = cc$rms_xabkey;
    hxab.xab$b_dtp = XAB$C_STG;
    hxab.xab$w_pos0 = 0;
    hxab.xab$b_siz0 = ST_MREC_KEY_SIZE;
    hxab.xab$b_ref = 0;
    hfab.fab$l_xab = (void *) &hxab;
    hfab.fab$l_fna = (char *) path;
    hfab.fab$b_fns = (unsigned char) strlen(path);
    hfab.fab$b_org = FAB$C_IDX;
    hfab.fab$b_rfm = FAB$C_FIX;
    hfab.fab$w_mrs = ST_MREC_SIZE;
    hfab.fab$b_bks = 12;   /* 6 KB buckets: four records each */
    hfab.fab$b_fac = writer ? (FAB$M_GET | FAB$M_PUT | FAB$M_UPD) : FAB$M_GET;
    hfab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD;
    hfab.fab$l_fop = FAB$M_CIF;
    st = sys$create(&hfab);
    if (!(st & 1)) return st;
    if (hfab.fab$w_mrs != ST_MREC_SIZE) { sys$close(&hfab); return RMS$_RSZ; }
    hrab = cc$rms_rab;
    hrab.rab$l_fab = &hfab;
    st = sys$connect(&hrab);
    if (!(st & 1)) { sys$close(&hfab); return st; }
    history_open = 1;
    return SS$_NORMAL;
}

int st_plat_history_get(unsigned int slot, unsigned char rec[ST_MREC_SIZE], st_err *e)
{
    static unsigned char key[ST_MREC_KEY_SIZE];   /* static: the RAB points at it */
    unsigned int st;
    if (!history_open) return 0;
    st_mrec_key(slot, key);
    hrab.rab$b_rac = RAB$C_KEY;
    hrab.rab$b_krf = 0;
    hrab.rab$l_kbf = (char *) key;
    hrab.rab$b_ksz = ST_MREC_KEY_SIZE;
    hrab.rab$l_rop = RAB$M_NLK | RAB$M_RRL;
    hrab.rab$l_ubf = (char *) rec;
    hrab.rab$w_usz = ST_MREC_SIZE;
    st = sys$get(&hrab);
    if (st == RMS$_RNF) return 0;
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return hrab.rab$w_rsz == ST_MREC_SIZE;
}

int st_plat_history_put(const unsigned char rec[ST_MREC_SIZE], st_err *e)
{
    unsigned int st;
    if (!history_open) { set_text(e, ST_E_INTERNAL, "no recording file"); return -1; }
    hrab.rab$b_rac = RAB$C_KEY;
    hrab.rab$l_rop = RAB$M_UIF | RAB$M_WAT;   /* replace the slot's record if present */
    hrab.rab$l_rbf = (char *) rec;
    hrab.rab$w_rsz = ST_MREC_SIZE;
    st = sys$put(&hrab);
    sys$free(&hrab);
    if (st & 1) st = sys$flush(&hrab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_recorder_init(const char *history_file, st_err *e)
{
    unsigned int all[2] = { 0xFFFFFFFFu, 0xFFFFFFFFu };
    unsigned int keep[2] = { PRV$M_TMPMBX | PRV$M_NETMBX, 0 };
    unsigned int cur[2] = { 0, 0 }, iosb[2], st;
    st_ile3 items[2];
    /* Off in the permanent mask too, so the DCL around the image does not get them
       back. The recorder never asks for one again. */
    sys$setprv(0, (void *) all, 1, 0);
    sys$setprv(1, (void *) keep, 1, 0);
    item(&items[0], JPI$_CURPRIV, cur, 8, 0);
    item_end(&items[1]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    if (!(st & 1) || (cur[0] & ~keep[0]) || cur[1]) {
        set_text(e, ST_E_INTERNAL, "cannot switch the recorder's privileges off");
        return -1;
    }
    if (!history_file || !*history_file) { set_text(e, ST_E_INTERNAL, "STEWARD_MONITOR_FILE is not defined"); return -1; }
    st = open_history(history_file, 1);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    set_text(e, ST_OK, "");
    return 0;
}

/* SYSPRV, which $PERSONA_CREATE needs to read the user's UAF record (GRPPRV within
   the service's own UIC group, SYSPRV for everyone else: PHASE1.md). The account
   holds it as authorized, not default, and it is on only around that one call (D2). */
static unsigned int sysprv[2] = { PRV$M_SYSPRV, 0 };

static char service_account[13];
static char service_image[64];          /* st_plat_service_image */
static unsigned int max_sys_group = 8;  /* SYSGEN MAXSYSGROUP, read at start-up */
static char steward_log[256];       /* Steward's audit log, read back for access history */
/* The D14 helper procedure, fixed: never taken from a logical name the service would
   translate through its group or system tables, which others could define. */
static char lnm_helper[256] = "STEWARD$ROOT:[COM]STEWARD_LNM.COM";
/* ... and resolved once, before any persona, to a physical device ("_DEV:", which
   is never translated) and a full directory: lnm_resolve_helper. The helper process
   translates whatever it is given in its own context, where a user- or
   supervisor-mode STEWARD$ROOT in the *viewer's* group table, or in the system
   table, comes first (probes/lnm_shadow.py, NOTES.md). Empty until resolved. */
static char lnm_helper_path[256];
/* The SYSGEN listing's procedure (Phase 10, D18), fixed and resolved the same way. */
static char sysgen_helper[256] = "STEWARD$ROOT:[COM]STEWARD_SYSGEN.COM";
static char sysgen_helper_path[256];
/* The licences' procedure (Phase 11, D19), fixed and resolved the same way. */
static char license_helper[256] = "STEWARD$ROOT:[COM]STEWARD_LICENSE.COM";
static char license_helper_path[256];
/* The installed products' procedure (Phase 12, D20), fixed and resolved the same way. */
static char product_helper[256] = "STEWARD$ROOT:[COM]STEWARD_PRODUCT.COM";
static char product_helper_path[256];
/* The error log's procedure (Phase 14, D23), fixed and resolved the same way. */
static char errlog_helper[256] = "STEWARD$ROOT:[COM]STEWARD_ERRLOG.COM";
static char errlog_helper_path[256];
/* Installing and removing products (Phase 12b, D26): the helper and the batch job's
   procedure, fixed and resolved the same way. */
static char pcsi_helper[256] = "STEWARD$ROOT:[COM]STEWARD_PCSI.COM";
static char pcsi_helper_path[256];
static char pcsi_job[256] = "STEWARD$ROOT:[COM]STEWARD_PCSI_JOB.COM";
static char pcsi_job_path[256];
/* Where the error log and CLUE's listings are: SYS$ERRORLOG, but for the live test's
   scratch copies (st_plat_vms_test_errlog_dir). */
static char errlog_dir[200] = "SYS$ERRORLOG:";

/* spec (with dflt, if not NULL, for what it leaves out) to a physical path in out:
   $PARSE and $SEARCH with NOCONCEAL, then the device's full name ("_DEV:", never
   translated), the directory, name and type, without the version. *dirlen, if not
   NULL, gets the length of the device and directory. A search list is searched, so
   out names the directory the file is really in: $ERASE and $RENAME act on a search
   list's first directory only (SYS$ERRORLOG, NOTES.md). The RMS status, or
   SS$_IVDEVNAM if the device has no physical name; out is "" unless it succeeded. */
static unsigned int phys_spec(const char *spec, const char *dflt, char *out, size_t outlen, size_t *dirlen)
{
    struct FAB fab = cc$rms_fab;
    struct NAM nam = cc$rms_nam;
    char esa[NAM$C_MAXRSS + 1], rsa[NAM$C_MAXRSS + 1], dev[64], devname[65];
    struct dsc$descriptor_s dd;
    unsigned short devlen = 0;
    unsigned int st, iosb[2];
    st_ile3 it[2];
    int n;

    out[0] = '\0';
    fab.fab$l_fna = (char *) spec;
    fab.fab$b_fns = (unsigned char) strlen(spec);
    if (dflt) { fab.fab$l_dna = (char *) dflt; fab.fab$b_dns = (unsigned char) strlen(dflt); }
    fab.fab$l_nam = &nam;
    nam.nam$l_esa = esa;
    nam.nam$b_ess = NAM$C_MAXRSS;
    nam.nam$l_rsa = rsa;
    nam.nam$b_rss = NAM$C_MAXRSS;
    nam.nam$b_nop = NAM$M_NOCONCEAL;
    st = sys$parse(&fab);
    if (st & 1) st = sys$search(&fab);
    if (!(st & 1)) return st;
    if (nam.nam$b_dev == 0 || nam.nam$b_dev >= sizeof dev) return SS$_IVDEVNAM;
    memcpy(dev, nam.nam$l_dev, nam.nam$b_dev);
    dev[nam.nam$b_dev] = '\0';
    desc(&dd, dev, (unsigned short) strlen(dev));
    item(&it[0], DVI$_FULLDEVNAM, devname, sizeof devname - 1, &devlen);
    item_end(&it[1]);
    st = sys$getdviw(0, 0, &dd, it, (void *) iosb, 0, 0, 0);
    if (st & 1) st = iosb[0] & 0xFFFF;
    if (!(st & 1) || devlen == 0 || devname[0] != '_') return SS$_IVDEVNAM;
    devname[devlen] = '\0';
    n = snprintf(out, outlen, "%s%.*s%.*s%.*s", devname, (int) nam.nam$b_dir, nam.nam$l_dir,
                 (int) nam.nam$b_name, nam.nam$l_name, (int) nam.nam$b_type, nam.nam$l_type);
    if (n < 0 || n >= (int) outlen) { out[0] = '\0'; return RMS$_FNM; }
    if (dirlen) *dirlen = strlen(devname) + nam.nam$b_dir;
    return SS$_NORMAL;
}

/* A helper procedure's spec to a physical path, as the service, before any persona
   ("" if it cannot be: the helper is then off, and the log says why). The directory,
   name and type, without the version: a kit installed later puts a new version there,
   and the pool is restarted with it anyway. */
static void resolve_procedure(const char *spec, char *out, size_t outlen, const char *what)
{
    char msg[120];
    unsigned int st = phys_spec(spec, NULL, out, outlen, NULL);
    if (st == SS$_IVDEVNAM) {
        snprintf(msg, sizeof msg, "the %s procedure's device has no physical name: it is off", what);
        st_plat_log(msg);
    } else if (!(st & 1)) {
        snprintf(msg, sizeof msg, "the %s procedure was not found: it is off", what);
        st_plat_log(msg);
    }
}

static void lnm_resolve_helper(void)
{
    resolve_procedure(lnm_helper, lnm_helper_path, sizeof lnm_helper_path, "logical-name helper");
    resolve_procedure(sysgen_helper, sysgen_helper_path, sizeof sysgen_helper_path, "SYSGEN helper");
    resolve_procedure(license_helper, license_helper_path, sizeof license_helper_path, "licence helper");
    resolve_procedure(product_helper, product_helper_path, sizeof product_helper_path, "products helper");
    resolve_procedure(errlog_helper, errlog_helper_path, sizeof errlog_helper_path, "error log helper");
    resolve_procedure(pcsi_helper, pcsi_helper_path, sizeof pcsi_helper_path, "PCSI helper");
    resolve_procedure(pcsi_job, pcsi_job_path, sizeof pcsi_job_path, "PCSI job");
}

/* For tests/vms/api_probe.c only, to run edited PCSI procedures before they are
   installed. STEWARD.EXE never calls it. */
void st_plat_vms_test_pcsi(const char *helper, const char *job)
{
    st_copy(pcsi_helper, sizeof pcsi_helper, helper);
    st_copy(pcsi_job, sizeof pcsi_job, job);
    lnm_resolve_helper();
}

/* For tests/vms/api_probe.c only, to run an edited error log procedure before it is
   installed. STEWARD.EXE never calls it. */
void st_plat_vms_test_errlog(const char *path)
{
    st_copy(errlog_helper, sizeof errlog_helper, path);
    lnm_resolve_helper();
}

/* For tests/vms/api_probe.c only: a directory of copies of ERRLOG.SYS and CLUE
   listings, so the live test renames and deletes those, not the system's (D24). */
void st_plat_vms_test_errlog_dir(const char *dir)
{
    st_copy(errlog_dir, sizeof errlog_dir, dir);
}

/* For tests/vms/api_probe.c only, to run an edited products procedure before it is
   installed. STEWARD.EXE never calls it. */
void st_plat_vms_test_product(const char *path)
{
    st_copy(product_helper, sizeof product_helper, path);
    lnm_resolve_helper();
}

/* For tests/vms/api_probe.c only, to run an edited licence procedure before it is
   installed. STEWARD.EXE never calls it. */
void st_plat_vms_test_license(const char *path)
{
    st_copy(license_helper, sizeof license_helper, path);
    lnm_resolve_helper();
}

/* For tests/vms/api_probe.c only, to run an edited SYSGEN procedure before it is
   installed. STEWARD.EXE never calls it. */
void st_plat_vms_test_sysgen(const char *path)
{
    st_copy(sysgen_helper, sizeof sysgen_helper, path);
    lnm_resolve_helper();
}

/* For tests/vms/api_probe.c only, to run an edited procedure before it is installed.
   STEWARD.EXE never calls it. */
void st_plat_vms_test_helper(const char *path)
{
    st_copy(lnm_helper, sizeof lnm_helper, path);
    lnm_resolve_helper();
}

const char *st_plat_service_account(void) { return service_account; }
const char *st_plat_service_image(void) { return service_image; }
unsigned int st_plat_max_sys_group(void) { return max_sys_group; }

/* For tests/vms/api_probe.c only. The probe runs in the work account, so it would
   take that for the service account, and "Steward's own processes" would mean the
   work account's (the real pool's STEWARD_19300 was stopped that way by
   phase8b_live.py, 2026-10-15). The live test names a test account instead.
   STEWARD.EXE never calls it. */
void st_plat_vms_test_svc_acct(const char *name)
{
    st_copy(service_account, sizeof service_account, name);
}

/* For tests/vms/api_probe.c only, likewise: the image whose processes count as
   Steward's own (st_plat_service_image), so a test can stand a process of its own in
   for a pool worker busy with a request. */
void st_plat_vms_test_svc_img(const char *image)
{
    st_proc_image_name(image, service_image, sizeof service_image);
}

/* For tests/vms/api_probe.c only, likewise: MAXSYSGROUP, so a test can make one of its
   own processes count as a system process rather than try a real one. */
void st_plat_vms_test_svc_grp(unsigned int group)
{
    max_sys_group = group;
}

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
        char img[256] = { 0 };
        unsigned short il = 0;
        st_ile3 it3[3];
        item(&it3[0], JPI$_USERNAME, u, 12, &ul);
        item(&it3[1], JPI$_IMAGNAME, img, sizeof img - 1, &il);
        item_end(&it3[2]);
        if (sys$getjpiw(0, 0, 0, it3, iosb, 0, 0) & 1) {
            blank_trim(u, ul, service_account, sizeof service_account);
            img[il] = '\0';
            st_proc_image_name(img, service_image, sizeof service_image);
        }
        (void) it;
        {   /* MAXSYSGROUP: kept at the default 8 if it cannot be read */
            unsigned int v = 0;
            item(&it3[0], SYI$_MAXSYSGROUP, &v, 4, 0);
            item_end(&it3[1]);
            if ((sys$getsyiw(0, 0, 0, it3, iosb, 0, 0) & 1) && (iosb[0] & 1)) max_sys_group = v;
        }
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
    if (cfg->history_file && *cfg->history_file) {
        /* Not fatal: without it the live monitoring still works, and the history
           says there is no recording. */
        st = open_history(cfg->history_file, 0);
        if (!(st & 1)) {
            char m[200], t[256];
            msgtext(st, t, sizeof t);
            snprintf(m, sizeof m, "cannot open the recording: %.150s", t);
            st_plat_log(m);
        }
    }
    lnm_resolve_helper();   /* as the service, before any persona */
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

int st_plat_password_max(void) { return UAI$C_MAX_PWD_LENGTH; }

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
   they need exactly 4 (8 gives BADPARAM). $GETRMI writes the return length as a
   longword, 2 bytes past an unsigned short (probes/probe_rmi.c, NOTES.md), so it gets
   one; $GETSYI writes a word into its low half (little-endian). */
static unsigned int item_u64(int rmi, unsigned short code, unsigned short size, unsigned long long *out)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    unsigned char buf[8] = { 0 };
    unsigned int len = 0;
    st_ile3 it[2];
    item(&it[0], code, buf, size, (unsigned short *) &len);
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

/* The next disk the dashboard lists: mounted, not foreign, not a shadow set member,
   not remote, not the memory-disk boot image. Its $DEVICE_SCAN name in name, its
   logical volume name in lv, its name as shown ("DKA0:") in device, and whether it is
   sysdev. 0 at the end of the scan. */
static int disk_next(unsigned int ctx[2], const char *sysdev, char name[65], char lv[32],
                     char *device, size_t devlen, int *system_disk)
{
    char full[65];
    unsigned short len;
    unsigned int devclass = DC$_DISK, st;
    struct dsc$descriptor_s nd;
    st_ile3 sel[2];
    const char *p;

    item(&sel[0], DVS$_DEVCLASS, &devclass, sizeof devclass, 0);
    item_end(&sel[1]);
    for (;;) {
        len = 0;
        desc(&nd, name, 64);
        st = sys$device_scan(&nd, &len, 0, sel, (void *) ctx);
        if (!(st & 1)) return 0;
        name[len] = '\0';
        if (!dvi_u32(name, DVI$_MNT) || dvi_u32(name, DVI$_FOR) || dvi_u32(name, DVI$_SHDW_MEMBER) ||
            dvi_u32(name, DVI$_REMOTE_DEVICE))
            continue;
        dvi_str(name, DVI$_LOGVOLNAM, lv, 32);
        if (!strncmp(lv, "SYS$MD", 6)) continue;                   /* memory-disk boot image */
        dvi_str(name, DVI$_FULLDEVNAM, full, sizeof full);
        p = strchr(full, '$');                                    /* "_NODE$DKA0:" -> "DKA0:" */
        p = p ? p + 1 : (full[0] == '_' ? full + 1 : full);
        st_copy(device, devlen, p);
        *system_disk = !strcmp(full, sysdev);
        return 1;
    }
}

static void system_disks(st_system *s)
{
    char name[65], sysdev[65], lv[32], device[32];
    unsigned int ctx[2] = { 0, 0 };
    int i, sys;

    dvi_str("SYS$SYSDEVICE", DVI$_FULLDEVNAM, sysdev, sizeof sysdev);
    while (s->ndisks < ST_MAX_DISKS && disk_next(ctx, sysdev, name, lv, device, sizeof device, &sys)) {
        st_disk *d = &s->disks[s->ndisks];
        unsigned long long maxblock, freeblocks;
        memset(d, 0, sizeof *d);
        dvi_str(name, DVI$_VOLNAM, d->label, sizeof d->label);
        st_copy(d->logical_volume, sizeof d->logical_volume, lv);
        st_copy(d->device, sizeof d->device, device);
        st_copy(d->filesystem, sizeof d->filesystem, acp_name(dvi_u32(name, DVI$_ACPTYPE)));
        maxblock = dvi_u32(name, DVI$_MAXBLOCK);
        freeblocks = dvi_u32(name, DVI$_FREEBLOCKS);
        d->total = maxblock * 512ull;
        d->free = freeblocks * 512ull;
        d->system_disk = sys;
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

/* Now, in UTC milliseconds ($GETTIM is local time; no struct timeval under
   /STANDARD=C99). */
static long long now_utc_ms(void)
{
    unsigned int q[2] = { 0, 0 };
    sys$gettim((void *) q);
    return (long long) ((((unsigned long long) q[1] << 32 | q[0]) - VMS_EPOCH_OFFSET) / 10000ull)
           - local_offset() * 1000;
}

int st_plat_system(st_system *s, st_err *e)
{
    unsigned long long v, pages = 0, pagesize = 0, fr = 0, mod = 0, pf = 0, pff = 0, sf = 0, sff = 0;
    unsigned int boot[2];

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
    s->sampled_at_ms = now_utc_ms();   /* when the idle ticks were read */
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

/* ================================================================ monitoring (D21)

   The counters MONITOR shows, from $GETRMI, which needs no privilege (probe_rmi,
   NOTES.md). Item sizes as the probe found them: the mode counters and the memory
   lists 8 bytes, the rest exactly 4 (8 gives BADPARAM). Every item goes in one call,
   so the mode counters are read together; each return length is a longword, which
   $GETRMI writes in full. Should OpenVMS refuse the list (an item this version does
   not know), each item is asked for alone and a refused one stays zero. */

typedef struct { unsigned short code, size; int kind, index; } mon_item;
enum { MK_MODE, MK_STATE, MK_COUNTER, MK_PROCS, MK_FREE, MK_MOD };

static const mon_item mon_items[] = {
    { RMI$_CPUINTSTK, 8, MK_MODE, ST_MON_INTERRUPT }, { RMI$_CPUMPSYNCH, 8, MK_MODE, ST_MON_MPSYNCH },
    { RMI$_CPUKERNEL, 8, MK_MODE, ST_MON_KERNEL },    { RMI$_CPUEXEC, 8, MK_MODE, ST_MON_EXEC },
    { RMI$_CPUSUPER, 8, MK_MODE, ST_MON_SUPER },      { RMI$_CPUUSER, 8, MK_MODE, ST_MON_USER },
    { RMI$_CPUIDLE, 8, MK_MODE, ST_MON_IDLE },
    { RMI$_CUR, 4, MK_STATE, ST_MON_CUR },     { RMI$_COM, 4, MK_STATE, ST_MON_COM },
    { RMI$_COMO, 4, MK_STATE, ST_MON_COMO },   { RMI$_LEF, 4, MK_STATE, ST_MON_LEF },
    { RMI$_LEFO, 4, MK_STATE, ST_MON_LEFO },   { RMI$_HIB, 4, MK_STATE, ST_MON_HIB },
    { RMI$_HIBO, 4, MK_STATE, ST_MON_HIBO },   { RMI$_SUSP, 4, MK_STATE, ST_MON_SUSP },
    { RMI$_SUSPO, 4, MK_STATE, ST_MON_SUSPO }, { RMI$_PFW, 4, MK_STATE, ST_MON_PFW },
    { RMI$_MWAIT, 4, MK_STATE, ST_MON_MWAIT }, { RMI$_CEF, 4, MK_STATE, ST_MON_CEF },
    { RMI$_COLPG, 4, MK_STATE, ST_MON_COLPG }, { RMI$_FPG, 4, MK_STATE, ST_MON_FPG },
    { RMI$_PROCS, 4, MK_PROCS, 0 },
    { RMI$_FRLIST, 8, MK_FREE, 0 }, { RMI$_MODLIST, 8, MK_MOD, 0 },
    { RMI$_FAULTS, 4, MK_COUNTER, ST_MON_FAULTS },   { RMI$_PREADIO, 4, MK_COUNTER, ST_MON_PREADIO },
    { RMI$_PWRITIO, 4, MK_COUNTER, ST_MON_PWRITIO }, { RMI$_ISWPCNT, 4, MK_COUNTER, ST_MON_ISWPCNT },
    { RMI$_DIRIO, 4, MK_COUNTER, ST_MON_DIRIO },     { RMI$_BUFIO, 4, MK_COUNTER, ST_MON_BUFIO },
    { RMI$_MBREADS, 4, MK_COUNTER, ST_MON_MBREADS }, { RMI$_MBWRITES, 4, MK_COUNTER, ST_MON_MBWRITES },
};
#define MON_NITEMS (sizeof mon_items / sizeof mon_items[0])

static unsigned int rmi_list(st_ile3 *it)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    st = sys$getrmi(0, 0, 0, it, iosb, 0, 0);
    if (st & 1) st = sys$synch(0, iosb);
    if (st & 1) st = iosb[0] & 0xFFFF;
    return st;
}

int st_plat_monitor(st_monitor *m, st_err *e)
{
    static unsigned long long val[MON_NITEMS];
    static unsigned int len[MON_NITEMS], ok[MON_NITEMS];
    static st_ile3 it[MON_NITEMS + 1];
    unsigned long long pages = 0, pagesize = 0, v;
    char name[65], sysdev[65], lv[32];
    unsigned int ctx[2] = { 0, 0 };
    size_t i;
    int sys, any = 0;

    memset(m, 0, sizeof *m);
    memset(val, 0, sizeof val);
    memset(len, 0, sizeof len);
    for (i = 0; i < MON_NITEMS; i++)
        item(&it[i], mon_items[i].code, &val[i], mon_items[i].size, (unsigned short *) &len[i]);
    item_end(&it[MON_NITEMS]);
    if (rmi_list(it) & 1) {
        for (i = 0; i < MON_NITEMS; i++) ok[i] = 1;
    } else {
        for (i = 0; i < MON_NITEMS; i++) {   /* one at a time: a refused item stays zero */
            st_ile3 one[2];
            one[0] = it[i];
            item_end(&one[1]);
            val[i] = 0;
            ok[i] = rmi_list(one) & 1;
        }
    }
    m->sampled_at_ms = now_utc_ms();
    if (item_u64(0, SYI$_ACTIVECPU_CNT, 8, &v) & 1) m->cpus = (unsigned int) v;
    item_u64(0, SYI$_MEMSIZE, 8, &pages);
    item_u64(0, SYI$_PAGE_SIZE, 8, &pagesize);
    m->mem_total = pages * pagesize;
    for (i = 0; i < MON_NITEMS; i++) {
        unsigned long long x = val[i];   /* little-endian: a 4-byte item is the low half */
        if (!ok[i]) continue;
        any = 1;
        switch (mon_items[i].kind) {
        case MK_MODE:    m->modes[mon_items[i].index] = (long long) x; break;
        case MK_STATE:   m->states[mon_items[i].index] = (unsigned int) x; break;
        case MK_COUNTER: m->counters[mon_items[i].index] = (unsigned int) x; break;
        case MK_PROCS:   m->processes = (unsigned int) x; break;
        case MK_FREE:    m->mem_free = x * pagesize; break;
        default:         m->mem_modified = x * pagesize; break;
        }
    }
    if (!any) { set_text(e, ST_E_INTERNAL, "$GETRMI failed"); return -1; }

    dvi_str("SYS$SYSDEVICE", DVI$_FULLDEVNAM, sysdev, sizeof sysdev);
    while (m->ndisks < ST_MAX_DISKS &&
           disk_next(ctx, sysdev, name, lv, m->disks[m->ndisks].device, sizeof m->disks[0].device, &sys)) {
        m->disks[m->ndisks].operations = dvi_u32(name, DVI$_OPCNT);
        if (sys && m->ndisks) {   /* the system disk first */
            st_mon_disk t = m->disks[m->ndisks];
            memmove(&m->disks[1], &m->disks[0], (size_t) m->ndisks * sizeof t);
            m->disks[0] = t;
        }
        m->ndisks++;
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
    if (plen < rec.uaf$b_pwd_length || plen > UAI$C_MAX_PWD_LENGTH) {   /* the template's minimum, before writing */
        sys$close(&fab);
        set_cond(e, SS$_INVPWDLEN);
        snprintf(e->text, sizeof e->text, "%%SYSTEM-F-INVPWDLEN, the password must be %u to %d characters",
                 (unsigned) rec.uaf$b_pwd_length, (int) UAI$C_MAX_PWD_LENGTH);
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

/* One log, open: its dates bound the connection; its lines, read only when it falls in
   the window, give the method, user and address. */
static unsigned int ax_ssh_read(const char *spec, unsigned int pid, const char *host, size_t hostlen,
                                long long since, long long until)
{
    static unsigned char line[1024];
    struct FAB f;
    struct RAB r;
    struct XABDAT dat;
    ax_ssh *c;
    int lines = 0;
    unsigned int st = ax_open(&f, &r, &dat, spec, 0, line, sizeof line - 1);
    if (!(st & 1)) return st;
    c = &ax_s[ax_ns];
    memset(c, 0, sizeof *c);
    c->pid = pid;
    {
        unsigned long long q;
        memcpy(&q, &dat.xab$q_cdt, 8);
        c->start = ax_time(q);
        memcpy(&q, &dat.xab$q_rdt, 8);
        c->end = ax_time(q);
    }
    if (c->end < c->start) c->end = c->start;
    ax_text((const unsigned char *) host, hostlen, c->host, sizeof c->host);
    if (c->end >= since - AX_NEAR && c->start <= until) {
        ax_ns++;
        while (lines++ < 400 && (ax_get(&r) & 1)) {
            line[r.rab$w_rsz] = '\0';
            ax_ssh_line(c, (char *) line);
        }
    }
    sys$close(&f);
    return SS$_NORMAL;
}

/* An SSH connection in the window: the server's NETWORK process under SSH$SSH. */
static int ax_ssh_wanted(const ax_proc *c, long long since, long long until)
{
    return !c->logfail && c->sub == ACR$K_NETWORK && ax_prefix(c->user, "SSH$")
        && (c->live || c->end >= since - AX_NEAR) && c->start <= until;
}

/* The log's own name, <node>_<client host>_<pid>.LOG, from what accounting gives. A
   dot is escaped (^.); a host with any character beyond letters, digits, - and _ (an
   IPv6 address, say) gets no name, and so no lookup that could misparse. 0: none. */
static int ax_ssh_name(char *out, size_t outlen, const char *node, const char *host, unsigned int pid)
{
    size_t o;
    const char *h;
    int n = snprintf(out, outlen, "SSH$ROOT:[VAR]%s_", node);
    if (!*node || !*host || n < 0 || (size_t) n >= outlen) return 0;
    o = (size_t) n;
    for (h = host; *h; h++) {
        unsigned char ch = (unsigned char) *h;
        int plain = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                    || ch == '-' || ch == '_';
        if (!plain && ch != '.') return 0;
        if (o + 3 >= outlen) return 0;
        if (ch == '.') out[o++] = '^';
        out[o++] = (char) ch;
    }
    n = snprintf(out + o, outlen - o, "_%08X.LOG", pid);
    return n > 0 && (size_t) n < outlen - o;
}

static long long ax_ms(void)
{
    unsigned long long q = 0;
    sys$gettim((void *) &q);
    return (long long) (q / 10000ull);
}

/* OpenSSH's logs, without walking SSH$ROOT:[VAR] where possible: a node can hold tens
   of thousands, and a walk of 27,651 while sshd added more took 1,995 s on IA64, where
   an open by exact name takes milliseconds (NOTES.md). So each connection accounting
   gave is looked up by name; only connections without a usable name (live ones, which
   carry no remote full name, and unusual hosts), or every log when accounting could
   not be read, need the walk, and it stops at AX_SSH_BUDGET_MS. *partial says the
   budget ran out, by name or by walk: what was read is shown, and the source is
   reported incomplete. */
#define AX_SSH_BUDGET_MS 5000
#define AX_SSH_WANT      64

static unsigned int ax_ssh_logs(long long since, long long until, int acct_read, int *partial)
{
    static const char spec[] = "SSH$ROOT:[VAR]*_*.LOG;*";
    char esa[256], rsa[256], node[16], name[256];
    unsigned int want[AX_SSH_WANT], st, rs;
    struct FAB fab = cc$rms_fab;
    struct NAM nam = cc$rms_nam;
    long long t0 = ax_ms();
    int i, nwant = 0, many = 0;

    *partial = 0;
    syi_str(SYI$_NODENAME, node, sizeof node);
    for (i = 0; i < ax_np && ax_ns < AX_SSH; i++) {
        ax_proc *c = &ax_p[i];
        if (!ax_ssh_wanted(c, since, until)) continue;
        if (!ax_ssh_name(name, sizeof name, node, c->full, c->pid)) {
            if (nwant < AX_SSH_WANT) want[nwant++] = c->pid; else many = 1;
            continue;
        }
        if (ax_ms() - t0 > AX_SSH_BUDGET_MS) { *partial = 1; return SS$_NORMAL; }
        st = ax_ssh_read(name, c->pid, c->full, strlen(c->full), since, until);
        if (st == RMS$_PRV) return st;   /* the viewer may not read these */
        /* RMS-E-FNF: purged, and a walk would not find it either */
    }
    if (acct_read && !nwant && !many) return SS$_NORMAL;

    fab.fab$l_fna = (char *) spec;
    fab.fab$b_fns = (unsigned char) (sizeof spec - 1);
    fab.fab$l_nam = &nam;
    nam.nam$l_esa = esa; nam.nam$b_ess = sizeof esa - 1;
    nam.nam$l_rsa = rsa; nam.nam$b_rss = sizeof rsa - 1;
    st = sys$parse(&fab);
    if (!(st & 1)) return st;
    while (ax_ns < AX_SSH && ((st = sys$search(&fab)) & 1)) {
        char fname[128], *u1, *u2, *end;
        unsigned long pid;
        size_t nl = nam.nam$b_name < sizeof fname ? nam.nam$b_name : sizeof fname - 1;
        if (ax_ms() - t0 > AX_SSH_BUDGET_MS) { *partial = 1; break; }
        memcpy(fname, nam.nam$l_name, nl);
        fname[nl] = '\0';
        /* <node>_<client host>_<pid>: the pid is 8 hex digits; anything else (the
           server's own SSH$SSHD_STARTUP.LOG) is not a connection. */
        u1 = strchr(fname, '_');
        u2 = strrchr(fname, '_');
        if (!u1 || u2 == u1 || strlen(u2 + 1) != 8) continue;
        pid = strtoul(u2 + 1, &end, 16);
        if (*end) continue;
        if (acct_read && !many) {        /* only the connections still without a log */
            for (i = 0; i < nwant && want[i] != (unsigned int) pid; i++) ;
            if (i == nwant) continue;
        }
        rsa[nam.nam$b_rsl] = '\0';
        rs = ax_ssh_read(rsa, (unsigned int) pid, u1 + 1, (size_t) (u2 - u1 - 1), since, until);
        if (rs == RMS$_PRV) { ax_search_end(&fab, &nam); return rs; }
        /* anything else: purged under us, or busy */
    }
    if (st & 1) ax_search_end(&fab, &nam);   /* stopped early, not at the end */
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
                   unsigned int src_cond[ST_SRC_COUNT], char src_text[ST_SRC_COUNT][96],
                   int src_partial[ST_SRC_COUNT], st_err *e)
{
    unsigned int st;
    int i, stop = 0;
    (void) e;
    for (i = 0; i < ST_SRC_COUNT; i++) { src_cond[i] = 0; src_text[i][0] = '\0'; src_partial[i] = 0; }
    ax_np = ax_ns = ax_nf = ax_ring = 0;
    ax_off = local_offset();
    if (!((st = ax_accounting(since, until)) & 1)) ax_cond(&src_cond[ST_SRC_ACCOUNTING], src_text[ST_SRC_ACCOUNTING], st);
    if (until >= st_plat_time() - 60) ax_live();
    st = ax_ssh_logs(since, until, src_cond[ST_SRC_ACCOUNTING] == 0, &src_partial[ST_SRC_SSH]);
    if (!(st & 1)) ax_cond(&src_cond[ST_SRC_SSH], src_text[ST_SRC_SSH], st);
    if (!((st = ax_journal(since, until)) & 1)) ax_cond(&src_cond[ST_SRC_AUDIT], src_text[ST_SRC_AUDIT], st);
    if (!((st = ax_steward(since, until, fn, ctx, &stop)) & 1)) ax_cond(&src_cond[ST_SRC_STEWARD], src_text[ST_SRC_STEWARD], st);
    if (!stop) ax_report(since, until, fn, ctx);
    return 0;
}

/* ================================================================ logical names (D14)

   Listing: a short-lived detached process, created under the persona, runs the fixed
   procedure STEWARD_LNM.COM. It reads a table and a pattern (data, never commands)
   from a request mailbox, and SHOW LOGICAL/FULL writes the listing to a reply
   mailbox, then "%%END%% <status>". Its process name, STW<request><reply><random> in
   hex, gives it
   the two mailbox units. Both mailboxes are the persona's, system and owner only.

   As found by probe (NOTES.md): LIB$SPAWN is refused under a persona; a subprocess
   waits for LIB$SPAWN's context; a mailbox as input makes LOGINOUT prompt; a mailbox
   as DCL's output gives RMS-F-DEV. Hence a detached process, a procedure file as its
   input and NLA0: as its output, and SHOW LOGICAL/OUTPUT= to the mailbox. */

#define LNM_REQ_MAXMSG 512
#define LNM_REP_MAXMSG 1024      /* reads never ask for more: MBTOOSML otherwise */
#define LNM_TRM_LEN    ACC$K_TERMLEN   /* the helper's termination message */
#define LNM_TIMEOUT_S  30
#define LNM_GRACE_S    2         /* after the helper ends: to read what it left queued */
#define LNM_MAX_MSGS   100000    /* lines, end-of-file messages included: a listing of
                                    MAX_NAMES names is far fewer */

static unsigned int mbx_unit(unsigned short chan, unsigned int *unit)
{
    unsigned int st;
    unsigned short iosb[4];
    st_ile3 it[2];
    *unit = 0;
    item(&it[0], DVI$_UNIT, unit, 4, 0);
    item_end(&it[1]);
    st = sys$getdviw(0, chan, 0, it, (void *) iosb, 0, 0, 0);
    if (st & 1) st = iosb[0];
    return st;
}

static unsigned int mbx_write(unsigned short chan, const char *s)
{
    unsigned short iosb[4];
    unsigned int st = sys$qiow(0, chan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0,
                               (void *) s, strlen(s), 0, 0, 0, 0);
    if (st & 1) st = iosb[0];
    return st;
}

static unsigned int lnm_timer(unsigned int ef, unsigned int seconds, unsigned long reqidt)
{
    unsigned int delta[2];
    delta[0] = (unsigned int) (-(long long) seconds * 10000000LL);
    delta[1] = 0xFFFFFFFFu;
    return sys$setimr(ef, (void *) delta, 0, reqidt, 0);
}

static unsigned int le32(const unsigned char *b)
{
    return (unsigned int) b[0] | ((unsigned int) b[1] << 8) | ((unsigned int) b[2] << 16) |
           ((unsigned int) b[3] << 24);
}

typedef void (*helper_line_fn)(const char *line, size_t len, void *ctx);

/* Run the fixed procedure at path in a short-lived detached process created under the
   persona, so it is the viewer (D14): send msgs to it as data, pass each line it writes
   to line_fn, until its last line, "%%END%% <status>". Returns 0 with *status_out (the
   procedure's own command's status), or -1 with e (no answer, a timeout, a refusal). */
static int helper_run(const char *path, const char *const *msgs, int nmsgs,
                      helper_line_fn line_fn, void *ctx, unsigned int *status_out, st_err *e)
{
    /* Event flags from LIB$GET_EF once, all in one cluster for $WFLOR: the reply
       read, the timer, the termination message. */
    static unsigned int efr, eft, efm;
    static char line[LNM_REP_MAXMSG + 1];
    static unsigned char trm[LNM_TRM_LEN];
    unsigned short reqchan = 0, repchan = 0, trmchan = 0, iosb[4], tiosb[4];
    unsigned int st, pid = 0, status = 0, final = 0, mask, ureq = 0, urep = 0, utrm = 0, nmsg = 0, state;
    unsigned long reqidt = (unsigned long) &efr;
    char prc[16];
    struct dsc$descriptor_s img, in, nl, pn;
    int done = 0, timed_out = 0, ended = 0, reading = 0, waiting = 0, tries, k;

    if (!path[0]) {   /* not found at start-up (the log says so) */
        set_text(e, ST_E_INTERNAL, "the helper procedure was not found when Steward started");
        return -1;
    }
    if (!efr && (!(lib$get_ef(&efr) & 1) || !(lib$get_ef(&eft) & 1) || !(lib$get_ef(&efm) & 1) ||
                 efr / 32 != eft / 32 || efr / 32 != efm / 32)) {
        /* Give back whichever were taken, so the next request tries afresh. */
        if (efr) lib$free_ef(&efr);
        if (eft) lib$free_ef(&eft);
        if (efm) lib$free_ef(&efm);
        efr = eft = efm = 0;
        set_text(e, ST_E_INTERNAL, "no event flags");
        return -1;
    }
    /* System and owner only (deny group and world). The owner is the persona. */
    st = sys$crembx(0, &reqchan, LNM_REQ_MAXMSG, 3 * LNM_REQ_MAXMSG, 0xFF00, 0, 0, 0, 0);
    if (st & 1) st = sys$crembx(0, &repchan, LNM_REP_MAXMSG, 16 * LNM_REP_MAXMSG, 0xFF00, 0, 0, 0, 0);
    if (st & 1) st = sys$crembx(0, &trmchan, LNM_TRM_LEN, 4 * LNM_TRM_LEN, 0xFF00, 0, 0, 0, 0);
    if (st & 1) st = mbx_unit(reqchan, &ureq);
    if (st & 1) st = mbx_unit(repchan, &urep);
    if (st & 1) st = mbx_unit(trmchan, &utrm);
    if (!(st & 1)) goto out;
    if (ureq > 0xFFFF || urep > 0xFFFF) { st = SS$_BADPARAM; goto out; }   /* 4 hex digits each */
    for (k = 0; k < nmsgs && (st & 1); k++) st = mbx_write(reqchan, msgs[k]);
    if (!(st & 1)) goto out;

    /* However the helper ends (its procedure done, LOGINOUT refusing it, its login
       procedure logging out), OpenVMS sends its termination message here, so a dead
       helper is noticed at once instead of at the deadline. */
    memset(tiosb, 0, sizeof tiosb);
    st = sys$qio(efm, trmchan, IO$_READVBLK, (void *) tiosb, 0, 0, trm, LNM_TRM_LEN, 0, 0, 0, 0);
    if (!(st & 1)) goto out;
    waiting = 1;

    desc(&img, "SYS$SYSTEM:LOGINOUT.EXE", 23);
    desc(&in, path, (unsigned short) strlen(path));
    desc(&nl, "NLA0:", 5);
    /* Its name: STW, the two mailbox units and a random part, all hex, 15 characters.
       Process names are unique in a UIC group, so a member of the viewer's group could
       otherwise create STW<req>_<rep> names ahead and make the group's listings fail
       (the Phase 7 review); a clash is tried again with another random part. */
    for (tries = 0; tries < 3; tries++) {
        unsigned short r = 0;
        if (!st_plat_random(&r, sizeof r)) { st = SS$_BADPARAM; break; }
        snprintf(prc, sizeof prc, "STW%04X%04X%04X", ureq, urep, (unsigned) r);
        desc(&pn, prc, (unsigned short) strlen(prc));
        st = sys$creprc(&pid, &img, &in, &nl, &nl, 0, 0, &pn, 4, 0, (unsigned short) utrm, PRC$M_DETACH, 0, 0);
        if (st != SS$_DUPLNAM) break;
    }
    if (!(st & 1)) { pid = 0; goto out; }

    /* The listing, line by line, until the procedure's last line or the deadline.
       The deadline is checked after every wake, whatever woke it: a helper whose
       login procedure keeps the reply mailbox full must not outlive it. */
    st = lnm_timer(eft, LNM_TIMEOUT_S, reqidt);
    if (!(st & 1)) goto out;
    mask = (1u << (efr % 32)) | (1u << (eft % 32)) | (1u << (efm % 32));
    for (;;) {
        if (!reading) {
            memset(iosb, 0, sizeof iosb);
            st = sys$qio(efr, repchan, IO$_READVBLK, (void *) iosb, 0, 0, line, LNM_REP_MAXMSG, 0, 0, 0, 0);
            if (!(st & 1)) break;
            reading = 1;
        }
        st = sys$wflor(efr, mask);
        if (!(st & 1)) break;
        if (reading && iosb[0]) {
            reading = 0;
            if (++nmsg > LNM_MAX_MSGS) { st = SS$_DATAOVERUN; break; }
            /* RMS writes an end-of-file message when SHOW LOGICAL/OUTPUT= closes the
               mailbox, and again after the last line: the procedure's own last line,
               not these, ends the listing. */
            if (iosb[0] != SS$_ENDOFFILE) {
                if (!(iosb[0] & 1)) { st = iosb[0]; break; }
                line[iosb[1]] = '\0';
                if (!strncmp(line, "%%END%% ", 8)) {
                    status = (unsigned int) strtoul(line + 8, NULL, 16);
                    status &= 0x0FFFFFFFu;   /* without DCL's "message already shown" bit */
                    done = 1;
                    break;
                }
                line_fn(line, iosb[1], ctx);   /* once the caller has enough, it only drains */
            }
        }
        if (waiting && tiosb[0] &&
            !((tiosb[0] & 1) && tiosb[1] >= 12 && (trm[0] | (trm[1] << 8)) == MSG$_DELPROC && le32(trm + 8) == pid)) {
            /* Not the helper's termination message: the mailbox is the viewer's, and
               their login procedure could write to it (the Phase 11 review). Read on. */
            if (++nmsg > LNM_MAX_MSGS) { st = SS$_DATAOVERUN; break; }
            sys$clref(efm);
            memset(tiosb, 0, sizeof tiosb);
            st = sys$qio(efm, trmchan, IO$_READVBLK, (void *) tiosb, 0, 0, trm, LNM_TRM_LEN, 0, 0, 0, 0);
            if (!(st & 1)) { waiting = 0; break; }
        } else if (waiting && tiosb[0]) {
            /* The helper has gone. What it wrote is already queued: a short grace to
               read it, then stop. Its final status explains a helper that never ran
               the procedure. Explicit offsets (ACCDEF): type at 0, status at 4, PID at 8. */
            waiting = 0;
            ended = 1;
            final = le32(trm + 4);
            sys$clref(efm);
            mask &= ~(1u << (efm % 32));
            sys$cantim(reqidt, 0);
            st = lnm_timer(eft, LNM_GRACE_S, reqidt);
            if (!(st & 1)) break;
        }
        if (sys$readef(eft, &state) == SS$_WASSET) { timed_out = !ended; break; }
    }

out:
    sys$cantim(reqidt, 0);
    /* Never leave one behind: unless OpenVMS has told us it is gone, delete it, even
       after its %%END%% (which the viewer's login procedure could have written, then
       stayed: the Phase 11 review). After a real %%END%% it is only logging out. */
    if (!ended && pid) sys$delprc(&pid, 0, 0);
    if (reading) { sys$cancel(repchan); sys$synch(efr, (void *) iosb); }
    if (waiting) { sys$cancel(trmchan); sys$synch(efm, (void *) tiosb); }
    if (reqchan) sys$dassgn(reqchan);
    if (repchan) sys$dassgn(repchan);
    if (trmchan) sys$dassgn(trmchan);
    if (timed_out) { set_cond(e, SS$_TIMEOUT); return -1; }
    if (!done) {
        if (!(st & 1)) set_cond(e, st);
        else if (final && !(final & 1)) set_cond(e, final);   /* e.g. the login refused */
        else set_text(e, ST_E_INTERNAL, "the listing process ended without an answer");
        return -1;
    }
    *status_out = status;
    return 0;
}

static void lnm_line(const char *line, size_t len, void *ctx)
{
    st_lnm_parse_line((st_lnm_parser *) ctx, line, len);
}

int st_plat_lnm_list(const char *table, const char *pattern, const char *privs,
                     st_lnm_cb fn, void *ctx, st_err *e)
{
    st_lnm_parser p;
    const char *msgs[3];
    unsigned int status = 0;
    msgs[0] = table; msgs[1] = pattern; msgs[2] = privs;
    st_lnm_parse_init(&p, fn, ctx);
    if (helper_run(lnm_helper_path, msgs, 3, lnm_line, &p, &status, e)) return -1;
    /* SHOW LOGICAL returns IVLOGTAB as a warning (%X158), SSDEF has it fatal (%X15C):
       the same message. Compare without the severity. */
    if ((status & ~7u) == (SS$_IVLOGTAB & ~7u)) status = SS$_IVLOGTAB;
    st_lnm_parse_end(&p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* SHOW LOGICAL's own failure */
    return 0;
}

/* ---- system parameters (Phase 10, D18): SYSGEN SHOW/ALL in the same helper ---- */

static void sysgen_line(const char *line, size_t len, void *ctx)
{
    st_sysgen_line((st_sysgen_parser *) ctx, line, len);
}

int st_plat_sysgen_list(const char *privs, st_param_cb fn, void *ctx, st_err *e)
{
    st_sysgen_parser p;
    const char *msgs[1];
    unsigned int status = 0;
    msgs[0] = privs;
    st_sysgen_init(&p, fn, ctx);
    if (helper_run(sysgen_helper_path, msgs, 1, sysgen_line, &p, &status, e)) return -1;
    st_sysgen_end(&p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* SYSGEN's own failure */
    return 0;
}

/* ---- licences (Phase 11, D19): SHOW LICENSE and LICENSE LIST in the same helper ---- */

static void license_line(const char *line, size_t len, void *ctx)
{
    st_license_line((st_license_parser *) ctx, line, len);
}

int st_plat_license_list(const char *privs, st_license_parser *p, char text[ST_LIC_PARTS][256], st_err *e)
{
    const char *msgs[1];
    unsigned int status = 0;
    int i;
    msgs[0] = privs;
    for (i = 0; i < ST_LIC_PARTS; i++) text[i][0] = '\0';
    if (helper_run(license_helper_path, msgs, 1, license_line, p, &status, e)) return -1;
    st_license_end(p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* the procedure refused */
    /* A part OpenVMS refused (the database, to most viewers) is shown, not an error. */
    for (i = 0; i < ST_LIC_PARTS; i++)
        if (p->seen[i] && !(p->status[i] & 1)) msgtext(p->status[i], text[i], 256);
    return 0;
}

/* ---- installed products (Phase 12, D20): PRODUCT SHOW in the same helper ---- */

static void product_line(const char *line, size_t len, void *ctx)
{
    st_product_line((st_product_parser *) ctx, line, len);
}

int st_plat_product_list(const char *privs, st_product_parser *p, char text[ST_PROD_PARTS][256], st_err *e)
{
    const char *msgs[1];
    unsigned int status = 0;
    int i;
    msgs[0] = privs;
    for (i = 0; i < ST_PROD_PARTS; i++) text[i][0] = '\0';
    if (helper_run(product_helper_path, msgs, 1, product_line, p, &status, e)) return -1;
    st_product_end(p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* the procedure refused */
    /* A part OpenVMS refused (without SYSLCK, both) is shown, not an error, with
       PRODUCT's own message: $GETMSG does not know PCSI's (NOTES.md). */
    for (i = 0; i < ST_PROD_PARTS; i++)
        if (p->seen[i] && !(p->status[i] & 1)) {
            if (p->message[i][0]) st_copy(text[i], 256, p->message[i]);
            else msgtext(p->status[i], text[i], 256);
        }
    return 0;
}

/* VMSINSTAL's own record: a text file anyone may read on the nodes seen (W:RE), read
   as the persona, as access history reads its files (D13). */
int st_plat_vmsinstal(st_vmsinstal_cb fn, void *ctx, unsigned int *cond, char text[256], st_err *e)
{
    static unsigned char line[1024];
    struct FAB fab;
    struct RAB rab;
    st_vmsinstal v;
    unsigned int st;
    (void) e;
    *cond = 0;
    text[0] = '\0';
    st = ax_open(&fab, &rab, 0, "SYS$UPDATE:VMSINSTAL.HISTORY", 0, line, sizeof line - 1);
    if (!(st & 1)) { *cond = st; msgtext(st, text, 256); return 0; }
    while ((st = ax_get(&rab)) & 1)
        if (st_vmsinstal_line((const char *) line, rab.rab$w_rsz, &v) && fn(&v, ctx)) break;
    sys$close(&fab);
    if (!(st & 1) && st != RMS$_EOF) { *cond = st; msgtext(st, text, 256); }
    return 0;
}

/* ---- the error log (Phase 14, D23) ---- */

static void errlog_line(const char *line, size_t len, void *ctx)
{
    st_elv_line((st_elv_parser *) ctx, line, len);
}

int st_plat_errlog(const char *privs, int op, unsigned int arg, const char *file, st_elv_parser *p, st_err *e)
{
    const char *msgs[4];
    char a[16], spec[240];
    unsigned int status = 0;
    snprintf(a, sizeof a, "%u", arg);
    /* The file as it really is, found as the persona: the helper then translates no
       logical name the viewer's group could shadow (as for the helper procedures).
       Finding it needs no access to the file, only to the directory, so not found is
       the truth (after a new log, until ERRFMT's next record); a viewer who may not
       read it gets ELV's refusal, now with the real PRV (NOTES.md). */
    {
        unsigned int st = phys_spec(file && *file ? file : "ERRLOG.SYS", errlog_dir, spec, sizeof spec, NULL);
        if (!(st & 1)) {
            set_cond(e, st);
            if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
            return -1;
        }
    }
    msgs[0] = privs;
    msgs[1] = op == ST_ELV_ENTRY ? "ENTRY" : "LIST";
    msgs[2] = a;
    msgs[3] = spec;   /* the directory fixed here, the name checked by the caller */
    if (helper_run(errlog_helper_path, msgs, 4, errlog_line, p, &status, e)) return -1;
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* the procedure refused */
    return 0;
}

/* CLUE's listings: SYS$ERRORLOG:CLUE$*.LIS as the persona, each opened for its first
   page. A listing it may not open refuses the lot: they share their protection. */
int st_plat_crashes(st_crash_cb fn, void *ctx, st_err *e)
{
    static unsigned char line[1024];
    static char esa[NAM$C_MAXRSS + 1], rsa[NAM$C_MAXRSS + 1];
    static st_clue_summary s;
    struct FAB sfab = cc$rms_fab, fab;
    struct NAM nam = cc$rms_nam;
    struct RAB rab;
    char name[64], full[NAM$C_MAXRSS + 1], pat[240];
    unsigned int st;
    int n = 0;

    snprintf(pat, sizeof pat, "%sCLUE$*.LIS", errlog_dir);
    sfab.fab$l_fna = pat;
    sfab.fab$b_fns = (unsigned char) strlen(pat);
    sfab.fab$l_nam = &nam;
    nam.nam$l_esa = esa;
    nam.nam$b_ess = NAM$C_MAXRSS;
    nam.nam$l_rsa = rsa;
    nam.nam$b_rss = NAM$C_MAXRSS;
    st = sys$parse(&sfab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    while ((st = sys$search(&sfab)) & 1) {
        size_t nl = (size_t) nam.nam$b_name + nam.nam$b_type;
        if (nl >= sizeof name || ++n > 5000) continue;
        memcpy(name, nam.nam$l_name, nl);
        name[nl] = '\0';
        if (!st_valid_clue_name(name)) continue;
        memcpy(full, rsa, nam.nam$b_rsl);
        full[nam.nam$b_rsl] = '\0';
        st = ax_open(&fab, &rab, 0, full, 0, line, sizeof line - 1);
        if (!(st & 1)) { set_cond(e, st); return -1; }
        st_clue_init(&s);
        while (!s.done && (ax_get(&rab) & 1)) st_clue_line(&s, (const char *) line, rab.rab$w_rsz);
        sys$close(&fab);
        if (fn(name, &s, ctx)) break;
    }
    if (!(st & 1) && st != RMS$_NMF && st != RMS$_FNF) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_crash_text(const char *name, st_text_cb fn, void *ctx, st_err *e)
{
    static unsigned char line[1024];
    struct FAB fab;
    struct RAB rab;
    unsigned int st = ax_open(&fab, &rab, 0, name, errlog_dir, line, sizeof line - 1);
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    while ((st = ax_get(&rab)) & 1)
        if (fn((const char *) line, rab.rab$w_rsz, ctx)) break;
    sys$close(&fab);
    if (!(st & 1) && st != RMS$_EOF) { set_cond(e, st); return -1; }
    return 0;
}

/* Found first, then erased by its full name: $ERASE alone looks only in a search
   list's first directory, and CLUE's listings are in SYS$COMMON, the second of
   SYS$ERRORLOG's (NOTES.md). */
int st_plat_crash_delete(const char *name, st_err *e)
{
    struct FAB fab = cc$rms_fab;
    char full[240];
    unsigned int st = phys_spec(name, errlog_dir, full, sizeof full, NULL);
    if (st & 1) {
        fab.fab$l_fna = full;
        fab.fab$b_fns = (unsigned char) strlen(full);
        st = sys$erase(&fab);
    }
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    return 0;
}

/* ERRLOG*.SYS in the error log's directory, each opened for its size and creation
   date: a file the viewer may not open refuses the lot (they share a protection). */
int st_plat_errlog_files(st_errlog_file_cb fn, void *ctx, st_err *e)
{
    static char esa[NAM$C_MAXRSS + 1], rsa[NAM$C_MAXRSS + 1];
    struct FAB sfab = cc$rms_fab, fab;
    struct NAM nam = cc$rms_nam;
    struct XABDAT dat;
    struct XABFHC fhc;
    char name[64], full[NAM$C_MAXRSS + 1], pat[240], when[24], iso[20];
    unsigned int st;
    unsigned short tl;
    struct dsc$descriptor_s td;
    int n = 0;

    snprintf(pat, sizeof pat, "%sERRLOG*.SYS", errlog_dir);
    sfab.fab$l_fna = pat;
    sfab.fab$b_fns = (unsigned char) strlen(pat);
    sfab.fab$l_nam = &nam;
    nam.nam$l_esa = esa;
    nam.nam$b_ess = NAM$C_MAXRSS;
    nam.nam$l_rsa = rsa;
    nam.nam$b_rss = NAM$C_MAXRSS;
    st = sys$parse(&sfab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    while ((st = sys$search(&sfab)) & 1) {
        size_t nl = (size_t) nam.nam$b_name + nam.nam$b_type;
        if (nl >= sizeof name || ++n > 1000) continue;
        memcpy(name, nam.nam$l_name, nl);
        name[nl] = '\0';
        if (!st_valid_errlog_name(name)) continue;
        memcpy(full, rsa, nam.nam$b_rsl);
        full[nam.nam$b_rsl] = '\0';
        fab = cc$rms_fab;
        dat = cc$rms_xabdat;
        fhc = cc$rms_xabfhc;
        dat.xab$l_nxt = (void *) &fhc;
        fab.fab$l_xab = (void *) &dat;
        fab.fab$l_fna = full;
        fab.fab$b_fns = (unsigned char) strlen(full);
        fab.fab$b_fac = FAB$M_GET;
        fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_UPI;
        st = sys$open(&fab);
        if (!(st & 1)) { set_cond(e, st); return -1; }
        sys$close(&fab);
        desc(&td, when, 23);
        tl = 0;
        iso[0] = '\0';
        if (sys$asctim(&tl, &td, (void *) &dat.xab$q_cdt, 0) & 1) {
            when[tl] = '\0';
            st_vms_time_iso(when[0] == ' ' ? when + 1 : when, iso);
        }
        if (fn(name, fhc.xab$l_ebk ? fhc.xab$l_ebk - (fhc.xab$w_ffb == 0) : 0, iso, ctx)) break;
    }
    if (!(st & 1) && st != RMS$_NMF && st != RMS$_FNF) { set_cond(e, st); return -1; }
    return 0;
}

/* ERRLOG.SYS to ERRLOG_<yyyymmdd>_<hhmm>.SYS, local time ($NUMTIM: the C RTL has no
   zone rules here, CLAUDE.md). ERRFMT does not hold it open (PHASE14.md). */
int st_plat_errlog_rename(char newname[32], st_err *e)
{
    struct FAB ofab = cc$rms_fab, nfab = cc$rms_fab;
    unsigned short t[7];
    char oldspec[240], newspec[240];
    size_t dirlen = 0;
    unsigned int st;
    newname[0] = '\0';
    if (!(sys$numtim(t, 0) & 1)) { set_text(e, ST_E_INTERNAL, "no time"); return -1; }
    st_errlog_renamed(t[0], t[1], t[2], t[3], t[4], newname);
    /* Found first, and renamed in the directory it is in: $RENAME alone would take a
       search list's first directory for both names (NOTES.md). */
    st = phys_spec("ERRLOG.SYS", errlog_dir, oldspec, sizeof oldspec, &dirlen);
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    snprintf(newspec, sizeof newspec, "%.*s%s", (int) dirlen, oldspec, newname);
    ofab.fab$l_fna = oldspec;
    ofab.fab$b_fns = (unsigned char) strlen(oldspec);
    nfab.fab$l_fna = newspec;
    nfab.fab$b_fns = (unsigned char) strlen(newspec);
    st = sys$rename(&ofab, 0, 0, &nfab);
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    return 0;
}

/* OPCOM's log: the newest SYS$MANAGER:OPERATOR.LOG, shared with OPCOM, which has it
   open for writing. */
int st_plat_opcom(st_opcom_parser *p, char file[96], st_err *e)
{
    static unsigned char line[4096];
    static char rsa[NAM$C_MAXRSS + 1];
    struct FAB fab = cc$rms_fab;
    struct RAB rab = cc$rms_rab;
    struct NAM nam = cc$rms_nam;
    unsigned int st;
    char full[240];
    file[0] = '\0';
    /* Found first, then opened by its physical name: opened through SYS$MANAGER, a
       search list, a version the viewer may not read is reported as not found
       (NOTES.md); opened where it is, OpenVMS says PRV. */
    st = phys_spec("OPERATOR.LOG", "SYS$MANAGER:", full, sizeof full, NULL);
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    fab.fab$l_fna = full;
    fab.fab$b_fns = (unsigned char) strlen(full);
    fab.fab$l_nam = &nam;
    nam.nam$l_rsa = rsa;
    nam.nam$b_rss = NAM$C_MAXRSS;
    fab.fab$b_fac = FAB$M_GET;
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_UPI;
    st = sys$open(&fab);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    if (nam.nam$b_rsl < 96) { memcpy(file, rsa, nam.nam$b_rsl); file[nam.nam$b_rsl] = '\0'; }
    rab.rab$l_fab = &fab;
    rab.rab$l_ubf = (char *) line;
    rab.rab$w_usz = sizeof line - 1;
    rab.rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    st = sys$connect(&rab);
    if (!(st & 1)) { sys$close(&fab); set_cond(e, st); return -1; }
    while ((st = ax_get(&rab)) & 1) st_opcom_line(p, (const char *) line, rab.rab$w_rsz);
    sys$close(&fab);
    st_opcom_end(p);
    if (!(st & 1) && st != RMS$_EOF) { set_cond(e, st); return -1; }
    return 0;
}

/* Every device's error count ($DEVICE_SCAN, $GETDVI ERRCNT: no privilege); those with
   any. Named as the dashboard names disks ("DKA0:"). */
int st_plat_device_errors(st_deverr_cb fn, void *ctx, int *scanned, st_err *e)
{
    unsigned int dctx[2] = { 0, 0 }, st, errs;
    char name[65], full[65];
    unsigned short len;
    struct dsc$descriptor_s nd;
    st_dev_errors d;
    const char *q;
    (void) e;
    *scanned = 0;
    for (;;) {
        len = 0;
        desc(&nd, name, 64);
        st = sys$device_scan(&nd, &len, 0, 0, (void *) dctx);
        if (!(st & 1)) break;
        name[len] = '\0';
        if (++*scanned > 100000) break;
        errs = dvi_u32(name, DVI$_ERRCNT);
        if (!errs) continue;
        dvi_str(name, DVI$_FULLDEVNAM, full, sizeof full);
        q = strchr(full, '$');
        q = q ? q + 1 : (full[0] == '_' ? full + 1 : full);
        st_copy(d.device, sizeof d.device, q[0] ? q : name);
        d.errors = errs;
        if (fn(&d, ctx)) break;
    }
    return 0;
}

/* ---- installing and removing products (Phase 12b, D26) ---- */

static void pcsi_find_line(const char *line, size_t len, void *ctx)
{
    st_product_line((st_product_parser *) ctx, line, len);
}

int st_plat_product_find(const char *privs, const char *source, st_product_parser *p, char text[256], st_err *e)
{
    const char *msgs[9];
    unsigned int status = 0;
    text[0] = '\0';
    msgs[0] = privs; msgs[1] = "FIND"; msgs[2] = source;
    msgs[3] = msgs[4] = msgs[5] = msgs[6] = msgs[7] = msgs[8] = "-";
    if (helper_run(pcsi_helper_path, msgs, 9, pcsi_find_line, p, &status, e)) return -1;
    st_product_end(p);
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* the procedure refused */
    /* PRODUCT's message whenever it gave one: "%PCSIUI-I-NOMATCH, no products were
       found" has a success status (%X0652A043). */
    if (p->message[ST_PROD_KITS][0]) st_copy(text, 256, p->message[ST_PROD_KITS]);
    else if (!st_product_ok(p, ST_PROD_KITS)) msgtext(p->status[ST_PROD_KITS], text, 256);
    return 0;
}

typedef struct { unsigned int entry, submit; int have_submit; char log[40], message[256]; } pcsi_job_ctx;

static void pcsi_job_line(const char *line, size_t len, void *ctx)
{
    pcsi_job_ctx *jc = ctx;
    char buf[300];
    if (len >= sizeof buf) len = sizeof buf - 1;
    memcpy(buf, line, len);
    buf[len] = '\0';
    if (!strncmp(buf, "%%ENTRY%% ", 10)) jc->entry = (unsigned int) strtoul(buf + 10, NULL, 10);
    else if (!strncmp(buf, "%%LOG%% ", 8)) st_copy(jc->log, sizeof jc->log, buf + 8);
    else if (!strncmp(buf, "%%SUBMIT%% ", 11)) { jc->submit = (unsigned int) strtoul(buf + 11, NULL, 16); jc->have_submit = 1; }
    else if (buf[0] == '%' && !jc->message[0]) st_copy(jc->message, sizeof jc->message, buf);   /* SUBMIT's own message */
}

int st_plat_product_job(const char *privs, int remove, const st_pcsi_id *id, const char *source,
                        const char *destination, unsigned int *entry, char logname[40], st_err *e)
{
    const char *msgs[9];
    pcsi_job_ctx jc;
    unsigned int status = 0;
    *entry = 0;
    logname[0] = '\0';
    if (!pcsi_job_path[0]) { set_text(e, ST_E_INTERNAL, "the PCSI job procedure was not found when Steward started"); return -1; }
    memset(&jc, 0, sizeof jc);
    msgs[0] = privs;
    msgs[1] = remove ? "REMOVE" : "INSTALL";
    msgs[2] = remove || !source || !*source ? "-" : source;
    msgs[3] = id->producer; msgs[4] = id->base; msgs[5] = id->name;
    msgs[6] = remove || !id->version[0] ? "-" : id->version;
    msgs[7] = remove || !destination || !*destination ? "-" : destination;
    msgs[8] = pcsi_job_path;
    if (helper_run(pcsi_helper_path, msgs, 9, pcsi_job_line, &jc, &status, e)) return -1;
    if (!(status & 1)) { set_cond(e, status); return -1; }   /* the procedure refused */
    if (!jc.have_submit || !(jc.submit & 1) || !jc.entry || !st_valid_pcsi_log(jc.log)) {
        set_cond(e, jc.have_submit && !(jc.submit & 1) ? (jc.submit & 0x0FFFFFFFu) : SS$_ABORT);
        if (e->cond == RMS$_DNF) e->kind = ST_E_CONFLICT;   /* no login directory: the account's state */
        if (jc.message[0]) st_copy(e->text, sizeof e->text, jc.message);
        return -1;
    }
    *entry = jc.entry;
    st_copy(logname, 40, jc.log);
    return 0;
}

int st_plat_text_file(const char *spec, st_text_cb fn, void *ctx, st_err *e)
{
    static unsigned char line[4096];
    struct FAB fab;
    struct RAB rab;
    unsigned int st = ax_open(&fab, &rab, 0, spec, 0, line, sizeof line - 1);
    if (!(st & 1)) {
        set_cond(e, st);
        if (st == RMS$_FNF) e->kind = ST_E_NOTFOUND;
        return -1;
    }
    while ((st = ax_get(&rab)) & 1)
        if (fn((const char *) line, rab.rab$w_rsz, ctx)) break;
    sys$close(&fab);
    if (!(st & 1) && st != RMS$_EOF) { set_cond(e, st); return -1; }
    return 0;
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

/* Only a real shareable table: one listed with the table attribute in
   LNM$SYSTEM_DIRECTORY. Not a search list of tables (which could name the process
   table, the service's own), not a process or job table of this process. Not the
   directory itself either: it has the table attribute, but its names are tables,
   listed by GET logicals/tables. And not a name this process's directory also has:
   $TRNLNM, $CRELNM and $DELLNM look there first, so it would send the call
   elsewhere. The table is uppercase (st_valid_lnm_table). */
static int lnm_real_table(const char *table, st_err *e)
{
    struct dsc$descriptor_s tab, dir, pdir;
    unsigned int attrs = 0, st;
    st_ile3 it[2];
    if (!strcmp(table, "LNM$SYSTEM_DIRECTORY")) { set_cond(e, SS$_NOLOGTAB); return -1; }
    desc(&tab, table, (unsigned short) strlen(table));
    desc(&pdir, "LNM$PROCESS_DIRECTORY", 21);
    item(&it[0], LNM$_ATTRIBUTES, &attrs, 4, 0);
    item_end(&it[1]);
    st = sys$trnlnm(0, &pdir, &tab, 0, it);
    if (st != SS$_NOLOGNAM) { set_cond(e, (st & 1) ? SS$_NOLOGTAB : st); return -1; }
    desc(&dir, "LNM$SYSTEM_DIRECTORY", 20);
    attrs = 0;
    st = sys$trnlnm(0, &dir, &tab, 0, it);
    if (st == SS$_NOLOGNAM || ((st & 1) && !(attrs & LNM$M_TABLE))) { set_cond(e, SS$_NOLOGTAB); return -1; }
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_lnm_get(const char *table, const char *name, int mode, st_lnm *out,
                    char table_out[ST_LNM_TABLE_MAX + 1], st_err *e)
{
    static const char *const modes[] = { "kernel", "exec", "super", "user" };
    struct dsc$descriptor_s tab, nam;
    unsigned int attrs = 0, index = 0, maxidx = 0, st;
    unsigned char acmode = 0, want = (unsigned char) mode;
    unsigned short slen = 0, tlen = 0;
    char string[ST_LNM_NAME_MAX + 1], tname[ST_LNM_TABLE_MAX + 1];
    st_ile3 it[7];

    if (lnm_real_table(table, e)) return -1;
    desc(&tab, table, (unsigned short) strlen(table));

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
        /* At a mode, $TRNLNM ignores outer modes and gives the outermost of the
           rest: the name is at that mode only if it says so. */
        st = sys$trnlnm(0, &tab, &nam, mode >= 0 ? &want : 0, it);
        if (st == SS$_NOLOGNAM) { set_cond(e, st); return 0; }
        if (!(st & 1)) { set_cond(e, st); return -1; }
        if (index == 0 && mode >= 0 && acmode != want) { set_cond(e, SS$_NOLOGNAM); return 0; }
        if (index == 0) {
            if (maxidx > 127) maxidx = 127;
            st_copy(out->mode, sizeof out->mode, acmode < 4 ? modes[acmode] : "?");
            lnm_attrs(attrs, 1, out->attributes, sizeof out->attributes);
            tname[tlen] = '\0';
            /* Only in the table that was checked: $TRNLNM resolves the table name
               through LNM$PROCESS_DIRECTORY first, so a process-directory name that
               shadowed it would send the lookup elsewhere. */
            if (strcmp(tname, table)) { set_cond(e, SS$_NOLOGTAB); return -1; }
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

/* ---- changes (Phase 7b, D15) ---- */

/* An inner mode needs SYSNAM switched on in the persona: without it OpenVMS quietly
   uses user mode instead, for $CRELNM and $DELLNM alike (probe_crelnm, NOTES.md). */
static int lnm_mode_allowed(int mode, st_err *e)
{
    unsigned int priv[2] = { 0, 0 }, iosb[2], st;
    st_ile3 it[2];
    if (mode == ST_LNM_USER) return 0;
    if (mode != ST_LNM_SUPER && mode != ST_LNM_EXEC) { set_cond(e, SS$_BADPARAM); return -1; }
    item(&it[0], JPI$_CURPRIV, priv, 8, 0);
    item_end(&it[1]);
    st = sys$getjpiw(0, 0, 0, it, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    if (!(st & 1)) { set_cond(e, st); return -1; }
    if (!(priv[0] & PRV$M_SYSNAM)) { set_cond(e, SS$_NOSYSNAM); return -1; }
    return 0;
}

int st_plat_lnm_modes(const char *table, const char *name, st_err *e)
{
    struct dsc$descriptor_s tab, nam;
    unsigned int st;
    unsigned char m, got;
    unsigned short tlen;
    char tname[ST_LNM_TABLE_MAX + 1];
    st_ile3 it[3];
    int bits = 0;

    if (lnm_real_table(table, e)) return -1;
    desc(&tab, table, (unsigned short) strlen(table));
    desc(&nam, name, (unsigned short) strlen(name));
    /* $TRNLNM at a mode ignores names at outer modes and gives the outermost of the
       rest: it is at that mode exactly if it says so. */
    for (m = 0; m <= 3; m++) {
        got = 9;
        tlen = 0;
        item(&it[0], LNM$_ACMODE, &got, 1, 0);
        item(&it[1], LNM$_TABLE, tname, ST_LNM_TABLE_MAX, &tlen);
        item_end(&it[2]);
        st = sys$trnlnm(0, &tab, &nam, &m, it);
        if (st == SS$_NOLOGNAM) continue;
        if (!(st & 1)) { set_cond(e, st); return -1; }
        tname[tlen] = '\0';
        if (strcmp(tname, table)) { set_cond(e, SS$_NOLOGTAB); return -1; }
        if (got == m) bits |= 1 << m;
    }
    return bits;
}

int st_plat_lnm_define(const st_lnm_def *d, st_err *e)
{
    struct dsc$descriptor_s tab, nam;
    unsigned int attr = 0, st, eqattr[ST_LNM_MAXEQ];
    unsigned char mode = (unsigned char) d->mode;
    st_ile3 it[2 * ST_LNM_MAXEQ + 1];
    int i, n = 0;

    if (lnm_real_table(d->table, e)) return -1;
    if (lnm_mode_allowed(d->mode, e)) return -1;
    if (d->neq < 1 || d->neq > ST_LNM_MAXEQ) { set_cond(e, SS$_BADPARAM); return -1; }
    if (d->attrs & ST_LNM_CONFINE) attr |= LNM$M_CONFINE;
    if (d->attrs & ST_LNM_NO_ALIAS) attr |= LNM$M_NO_ALIAS;
    /* Each equivalence's attributes item applies to the string items after it. */
    for (i = 0; i < d->neq; i++) {
        eqattr[i] = ((d->eq[i].attrs & ST_LNM_CONCEALED) ? LNM$M_CONCEALED : 0) |
                    ((d->eq[i].attrs & ST_LNM_TERMINAL) ? LNM$M_TERMINAL : 0);
        item(&it[n++], LNM$_ATTRIBUTES, &eqattr[i], 4, 0);
        item(&it[n++], LNM$_STRING, (void *) d->eq[i].value, (unsigned short) strlen(d->eq[i].value), 0);
    }
    item_end(&it[n]);
    desc(&tab, d->table, (unsigned short) strlen(d->table));
    desc(&nam, d->name, (unsigned short) strlen(d->name));
    st = sys$crelnm(&attr, &tab, &nam, &mode, it);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return st == SS$_SUPERSEDE ? 2 : 1;
}

int st_plat_lnm_deassign(const char *table, const char *name, int mode, st_err *e)
{
    struct dsc$descriptor_s tab, nam;
    unsigned char m = (unsigned char) mode;
    unsigned int st;

    if (lnm_real_table(table, e)) return -1;
    if (lnm_mode_allowed(mode, e)) return -1;
    desc(&tab, table, (unsigned short) strlen(table));
    desc(&nam, name, (unsigned short) strlen(name));
    st = sys$dellnm(&tab, &nam, &m);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

/* ================================================================ processes (Phase 8, D16) */

/* $GETJPI's answers for one process, before they are tidied into an st_proc. */
typedef struct {
    unsigned int pid, uic, state, pri, prib, mode, owner, cputim, dirio, bufio, pageflts;
    unsigned int login[2];
    char name[16], user[13], term[16], image[256];
    unsigned short l_name, l_user, l_term, l_image;
} proc_raw;

static int proc_items(st_ile3 *it, proc_raw *r)
{
    int n = 0;
    memset(r, 0, sizeof *r);
    item(&it[n++], JPI$_PID, &r->pid, 4, 0);
    item(&it[n++], JPI$_PRCNAM, r->name, sizeof r->name - 1, &r->l_name);
    item(&it[n++], JPI$_USERNAME, r->user, sizeof r->user - 1, &r->l_user);
    item(&it[n++], JPI$_UIC, &r->uic, 4, 0);
    item(&it[n++], JPI$_STATE, &r->state, 4, 0);
    item(&it[n++], JPI$_PRI, &r->pri, 4, 0);
    item(&it[n++], JPI$_PRIB, &r->prib, 4, 0);
    item(&it[n++], JPI$_MODE, &r->mode, 4, 0);
    item(&it[n++], JPI$_OWNER, &r->owner, 4, 0);
    item(&it[n++], JPI$_TERMINAL, r->term, sizeof r->term - 1, &r->l_term);
    item(&it[n++], JPI$_IMAGNAME, r->image, sizeof r->image - 1, &r->l_image);
    item(&it[n++], JPI$_CPUTIM, &r->cputim, 4, 0);
    item(&it[n++], JPI$_DIRIO, &r->dirio, 4, 0);
    item(&it[n++], JPI$_BUFIO, &r->bufio, 4, 0);
    item(&it[n++], JPI$_PAGEFLTS, &r->pageflts, 4, 0);
    item(&it[n++], JPI$_LOGINTIM, r->login, 8, 0);
    return n;
}

static void proc_from_raw(const proc_raw *r, st_proc *p)
{
    memset(p, 0, sizeof *p);
    p->pid = r->pid;
    blank_trim(r->name, r->l_name, p->name, sizeof p->name);
    blank_trim(r->user, r->l_user, p->username, sizeof p->username);
    p->uic = r->uic;
    p->state = (int) r->state;
    p->pri = (int) r->pri;
    p->prib = (int) r->prib;
    p->mode = (int) r->mode;
    p->subprocess = r->owner != 0;
    blank_trim(r->term, r->l_term, p->terminal, sizeof p->terminal);
    blank_trim(r->image, r->l_image, p->image, sizeof p->image);
    p->cputim = r->cputim;
    p->dirio = r->dirio;
    p->bufio = r->bufio;
    p->pageflts = r->pageflts;
    p->login = unix_time(r->login);
}

/* The PID of the process serving the request: under the persona it reports the
   viewer's username and UIC, so it is never shown (PHASE8.md). */
static unsigned int proc_self(void)
{
    unsigned int pid = 0, iosb[2];
    st_ile3 it[2];
    item(&it[0], JPI$_PID, &pid, 4, 0);
    item_end(&it[1]);
    return (sys$getjpiw(0, 0, 0, it, iosb, 0, 0) & 1) ? pid : 0;
}

int st_plat_proc_enum(st_proc_cb fn, void *ctx, st_err *e)
{
    unsigned int wild = 0xFFFFFFFFu, iosb[2], st, self = proc_self();
    proc_raw r;
    st_proc p;
    st_ile3 it[20];
    for (;;) {
        item_end(&it[proc_items(it, &r)]);
        st = sys$getjpiw(0, &wild, 0, it, iosb, 0, 0);
        if (st & 1) st = iosb[0] & 0xFFFF;
        if (st == SS$_NOMOREPROC) break;
        if (st == SS$_NOPRIV || st == SS$_SUSPENDED) continue;   /* not the viewer's to see */
        if (!(st & 1)) { set_cond(e, st); return -1; }
        if (r.pid == self) continue;
        proc_from_raw(&r, &p);
        if (fn(&p, ctx)) break;
    }
    return 0;
}

int st_plat_proc_get(unsigned int pid, st_proc_detail *d, st_err *e)
{
    unsigned int iosb[2], st, i, target = pid, prccnt = 0, prclm = 0;
    unsigned int rights[2 * ST_MAX_IDS * 2], ppg = 0, gpg = 0;
    unsigned short rlen = 0;
    struct dsc$descriptor_s ds;
    proc_raw r;
    st_ile3 it[48];
    int n;
    static const unsigned short lm[ST_PQ_COUNT] = { JPI$_ASTLM, JPI$_BIOLM, JPI$_DIOLM, JPI$_FILLM,
        JPI$_PRCLM, JPI$_TQLM, JPI$_ENQLM, JPI$_BYTLM, JPI$_PGFLQUOTA };
    static const unsigned short cnt[ST_PQ_COUNT] = { JPI$_ASTCNT, JPI$_BIOCNT, JPI$_DIOCNT, JPI$_FILCNT,
        0, JPI$_TQCNT, JPI$_ENQCNT, JPI$_BYTCNT, JPI$_PAGFILCNT };

    memset(d, 0, sizeof *d);
    if (pid == proc_self()) { set_cond(e, SS$_NONEXPR); return -1; }
    n = proc_items(it, &r);
    item(&it[n++], JPI$_MASTER_PID, &d->master, 4, 0);
    item(&it[n++], JPI$_PRCCNT, &prccnt, 4, 0);
    item(&it[n++], JPI$_WSSIZE, &d->wssize, 4, 0);
    item(&it[n++], JPI$_PPGCNT, &ppg, 4, 0);
    item(&it[n++], JPI$_GPGCNT, &gpg, 4, 0);
    item(&it[n++], JPI$_CURPRIV, d->priv_cur, 8, 0);
    item(&it[n++], JPI$_AUTHPRIV, d->priv_auth, 8, 0);
    item(&it[n++], JPI$_PROCESS_RIGHTS, rights, sizeof rights, &rlen);
    for (i = 0; i < ST_PQ_COUNT; i++) {
        item(&it[n++], lm[i], &d->quota[i], 4, 0);
        if (cnt[i]) item(&it[n++], cnt[i], &d->left[i], 4, 0);
    }
    item(&it[n++], JPI$_PRCLM, &prclm, 4, 0);
    item_end(&it[n]);
    st = sys$getjpiw(0, &target, 0, it, iosb, 0, 0);
    if (st & 1) st = iosb[0] & 0xFFFF;
    if (!(st & 1)) { set_cond(e, st); return -1; }

    proc_from_raw(&r, &d->p);
    d->owner = r.owner;
    d->subprocesses = prccnt;
    d->wspages = ppg + gpg;
    d->left[ST_PQ_PRC] = prclm > prccnt ? prclm - prccnt : 0;   /* no PRCCNT-left item */
    for (i = 0; i + 1 < rlen / 4u && d->nids < ST_MAX_IDS; i += 2) {
        unsigned int id = rights[i], resid, attrib, ctx = 0;
        char name[32] = { 0 };
        unsigned short nlen = 0;
        if (!(id & 0x80000000u)) continue;   /* general identifiers, as SHOW PROCESS */
        desc(&ds, name, sizeof name - 1);
        if (sys$idtoasc(id, &nlen, &ds, &resid, &attrib, &ctx) & 1) {
            name[nlen] = '\0';
            st_copy(d->ids[d->nids++], sizeof d->ids[0], name);
        } else {
            snprintf(d->ids[d->nids++], sizeof d->ids[0], "%%X%08X", id);
        }
        sys$finish_rdb(&ctx);
    }
    return 0;
}

int st_plat_proc_stop(unsigned int pid, st_err *e)
{
    unsigned int target = pid, st;
    if (pid == proc_self()) { set_cond(e, SS$_NONEXPR); return -1; }
    st = sys$delprc(&target, 0, 0);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

/* ================================================================ queues (Phase 9, D17) */

/* One queue's items, for $GETQUI QUI$_DISPLAY_QUEUE. */
typedef struct {
    unsigned int flags, status, limit, executing, pending, holding, timed;
    char name[32], node[16], desc[256];
    unsigned short l_name, l_node, l_desc;
} queue_raw;

static int queue_items(st_ile3 *it, queue_raw *r)
{
    int n = 0;
    memset(r, 0, sizeof *r);
    item(&it[n++], QUI$_QUEUE_NAME, r->name, sizeof r->name - 1, &r->l_name);
    item(&it[n++], QUI$_QUEUE_FLAGS, &r->flags, 4, 0);
    item(&it[n++], QUI$_QUEUE_STATUS, &r->status, 4, 0);
    item(&it[n++], QUI$_SCSNODE_NAME, r->node, sizeof r->node - 1, &r->l_node);
    item(&it[n++], QUI$_QUEUE_DESCRIPTION, r->desc, sizeof r->desc - 1, &r->l_desc);
    item(&it[n++], QUI$_JOB_LIMIT, &r->limit, 4, 0);
    item(&it[n++], QUI$_EXECUTING_JOB_COUNT, &r->executing, 4, 0);
    item(&it[n++], QUI$_PENDING_JOB_COUNT, &r->pending, 4, 0);
    item(&it[n++], QUI$_HOLDING_JOB_COUNT, &r->holding, 4, 0);
    item(&it[n++], QUI$_TIMED_RELEASE_JOB_COUNT, &r->timed, 4, 0);
    return n;
}

static void queue_from_raw(const queue_raw *r, st_queue *q)
{
    memset(q, 0, sizeof *q);
    blank_trim(r->name, r->l_name, q->name, sizeof q->name);
    q->batch = (r->flags & QUI$M_QUEUE_BATCH) != 0;
    q->generic = (r->flags & QUI$M_QUEUE_GENERIC) != 0;
    q->status = r->status;
    blank_trim(r->node, r->l_node, q->node, sizeof q->node);
    blank_trim(r->desc, r->l_desc, q->description, sizeof q->description);
    q->job_limit = r->limit;
    q->executing = r->executing;
    q->pending = r->pending;
    q->holding = r->holding;
    q->timed = r->timed;
}

/* $GETQUI's status: a longword condition first (JBC$_ codes). */
static unsigned int qui(unsigned int func, unsigned int *ctx, st_ile3 *it)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    st = sys$getquiw(0, func, ctx, it, iosb, 0, 0);
    return (st & 1) ? iosb[0] : st;
}

int st_plat_queue_enum(st_queue_cb fn, void *ctx, st_err *e)
{
    static char search[] = "*";
    unsigned int qctx = 0xFFFFFFFFu, st;
    queue_raw r;
    st_queue q;
    st_ile3 it[13];
    int n, count;
    for (count = 0; count < 100000; count++) {   /* bounded, as every walk here */
        n = queue_items(it, &r);
        item(&it[n++], QUI$_SEARCH_NAME, search, 1, 0);
        item_end(&it[n]);
        st = qui(QUI$_DISPLAY_QUEUE, &qctx, it);
        if (st == JBC$_NOMOREQUE) break;
        if (!(st & 1)) { set_cond(e, st); qui(QUI$_CANCEL_OPERATION, &qctx, 0); return -1; }
        queue_from_raw(&r, &q);
        if (fn(&q, ctx)) break;
    }
    qui(QUI$_CANCEL_OPERATION, &qctx, 0);
    return 0;
}

/* One job's summary items, for QUI$_DISPLAY_JOB and QUI$_DISPLAY_ENTRY. */
typedef struct {
    unsigned int entry, status, submitted[2];
    char name[40], user[13], queue[32];
    unsigned short l_name, l_user, l_queue;
} job_raw;

static int job_items(st_ile3 *it, job_raw *r)
{
    int n = 0;
    memset(r, 0, sizeof *r);
    item(&it[n++], QUI$_ENTRY_NUMBER, &r->entry, 4, 0);
    item(&it[n++], QUI$_JOB_NAME, r->name, sizeof r->name - 1, &r->l_name);
    item(&it[n++], QUI$_USERNAME, r->user, sizeof r->user - 1, &r->l_user);
    item(&it[n++], QUI$_JOB_STATUS, &r->status, 4, 0);
    item(&it[n++], QUI$_SUBMISSION_TIME, r->submitted, 8, 0);
    item(&it[n++], QUI$_QUEUE_NAME, r->queue, sizeof r->queue - 1, &r->l_queue);
    return n;
}

static void job_from_raw(const job_raw *r, st_job *j)
{
    memset(j, 0, sizeof *j);
    j->entry = r->entry;
    j->status = r->status;
    if (!(r->status & QUI$M_JOB_INACCESSIBLE)) {   /* only what the viewer may read */
        blank_trim(r->name, r->l_name, j->name, sizeof j->name);
        blank_trim(r->user, r->l_user, j->username, sizeof j->username);
        j->submitted = unix_time(r->submitted);
        if (j->submitted < 0) j->submitted = 0;   /* all ones: none */
    }
    blank_trim(r->queue, r->l_queue, j->queue, sizeof j->queue);
}

int st_plat_queue_get(const char *name, st_queue *q, st_job_cb fn, void *ctx, st_err *e)
{
    unsigned int qctx = 0xFFFFFFFFu, st, all = QUI$M_SEARCH_ALL_JOBS, wild = QUI$M_SEARCH_WILDCARD, n;
    char search[32];
    queue_raw r;
    job_raw jr;
    st_job j;
    st_ile3 it[14];
    int k;

    st_copy(search, sizeof search, name);
    k = queue_items(it, &r);
    item(&it[k++], QUI$_SEARCH_NAME, search, (unsigned short) strlen(search), 0);
    /* WILDCARD keeps the search context for the job walk that follows; without it a
       queue named exactly gives no jobs (phase9_live.py, 2026-10-15). */
    item(&it[k++], QUI$_SEARCH_FLAGS, &wild, 4, 0);
    item_end(&it[k]);
    st = qui(QUI$_DISPLAY_QUEUE, &qctx, it);
    if (st == JBC$_NOMOREQUE || st == JBC$_NOSUCHQUE) { set_cond(e, JBC$_NOSUCHQUE); qui(QUI$_CANCEL_OPERATION, &qctx, 0); return -1; }
    if (!(st & 1)) { set_cond(e, st); qui(QUI$_CANCEL_OPERATION, &qctx, 0); return -1; }
    queue_from_raw(&r, q);
    /* Its jobs. An empty queue answers NOSUCHJOB, not NOMOREJOB (probe_qui): both end
       the walk, which is bounded besides. */
    for (n = 0; n < 100000; n++) {
        k = job_items(it, &jr);
        item(&it[k++], QUI$_SEARCH_FLAGS, &all, 4, 0);
        item_end(&it[k]);
        st = qui(QUI$_DISPLAY_JOB, &qctx, it);
        if (st == JBC$_NOMOREJOB || st == JBC$_NOSUCHJOB) break;
        if (!(st & 1)) { set_cond(e, st); qui(QUI$_CANCEL_OPERATION, &qctx, 0); return -1; }
        job_from_raw(&jr, &j);
        if (!j.queue[0]) st_copy(j.queue, sizeof j.queue, q->name);
        if (fn(&j, ctx)) break;
    }
    qui(QUI$_CANCEL_OPERATION, &qctx, 0);
    return 0;
}

int st_plat_job_get(unsigned int entry, st_job_detail *d, st_err *e)
{
    unsigned int qctx = 0xFFFFFFFFu, st, after[2] = { 0, 0 }, prio = 0, uic = 0, target = entry, n;
    unsigned int wild = QUI$M_SEARCH_WILDCARD;
    char acct[9], log[256], file[256];
    unsigned short l_acct = 0, l_log = 0, l_file = 0;
    job_raw jr;
    st_ile3 it[17];
    int k;

    memset(d, 0, sizeof *d);
    k = job_items(it, &jr);
    item(&it[k++], QUI$_SEARCH_NUMBER, &target, 4, 0);
    item(&it[k++], QUI$_SEARCH_FLAGS, &wild, 4, 0);   /* context for the file walk */
    item(&it[k++], QUI$_AFTER_TIME, after, 8, 0);
    item(&it[k++], QUI$_PRIORITY, &prio, 4, 0);
    item(&it[k++], QUI$_ACCOUNT_NAME, acct, sizeof acct - 1, &l_acct);
    item(&it[k++], QUI$_UIC, &uic, 4, 0);
    item(&it[k++], QUI$_LOG_SPECIFICATION, log, sizeof log - 1, &l_log);
    item_end(&it[k]);
    st = qui(QUI$_DISPLAY_ENTRY, &qctx, it);
    if (st == JBC$_NOSUCHJOB || st == JBC$_NOMOREJOB || st == JBC$_NOSUCHENT) {
        set_cond(e, st == JBC$_NOSUCHENT ? JBC$_NOSUCHENT : JBC$_NOSUCHJOB);
        qui(QUI$_CANCEL_OPERATION, &qctx, 0);
        return -1;
    }
    if (!(st & 1)) { set_cond(e, st); qui(QUI$_CANCEL_OPERATION, &qctx, 0); return -1; }
    if (jr.status & QUI$M_JOB_INACCESSIBLE) {
        qui(QUI$_CANCEL_OPERATION, &qctx, 0);
        set_cond(e, SS$_NOPRIV);
        return -1;
    }
    job_from_raw(&jr, &d->j);
    d->after = unix_time(after);
    if (d->after < 0) d->after = 0;
    d->priority = prio;
    blank_trim(acct, l_acct, d->account, sizeof d->account);
    d->uic = uic;
    blank_trim(log, l_log, d->log, sizeof d->log);
    /* Its files, in the same context. */
    for (n = 0; n < 1000 && d->nfiles < ST_JOB_FILES; n++) {
        l_file = 0;
        item(&it[0], QUI$_FILE_SPECIFICATION, file, sizeof file - 1, &l_file);
        item_end(&it[1]);
        st = qui(QUI$_DISPLAY_FILE, &qctx, it);
        if (!(st & 1)) break;   /* JBC$_NOMOREFILE */
        blank_trim(file, l_file, d->files[d->nfiles++], sizeof d->files[0]);
    }
    qui(QUI$_CANCEL_OPERATION, &qctx, 0);
    return 0;
}

/* ---- changes (Phase 9b): $SNDJBC, judged by the queue manager as the persona ---- */

static unsigned int sndjbc(unsigned short func, st_ile3 *it)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    st = sys$sndjbcw(0, func, 0, it, (void *) iosb, 0, 0);
    return (st & 1) ? iosb[0] : st;
}

int st_plat_job_change(unsigned int entry, int op, st_err *e)
{
    unsigned int target = entry, st;
    st_ile3 it[3];
    item(&it[0], SJC$_ENTRY_NUMBER, &target, 4, 0);
    if (op == ST_JOB_DELETE) {
        item_end(&it[1]);
        st = sndjbc(SJC$_DELETE_JOB, it);
    } else {
        item(&it[1], op == ST_JOB_HOLD ? SJC$_HOLD : SJC$_NO_HOLD, 0, 0, 0);
        item_end(&it[2]);
        st = sndjbc(SJC$_ALTER_JOB, it);
    }
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_queue_change(const char *name, int op, st_err *e)
{
    char q[32];
    unsigned int st;
    st_ile3 it[2];
    st_copy(q, sizeof q, name);
    item(&it[0], SJC$_QUEUE, q, (unsigned short) strlen(q), 0);
    item_end(&it[1]);
    st = sndjbc(op == ST_QUEUE_STOP ? SJC$_STOP_QUEUE : SJC$_START_QUEUE, it);
    if (!(st & 1)) { set_cond(e, st); return -1; }
    return 0;
}

int st_plat_startup_queues(char names[][32], int max)
{
    struct dsc$descriptor_s tab, nam;
    char batch[32] = "SYS$BATCH", next[32], targets[4096];
    unsigned short blen = 0, tlen = 0;
    unsigned int ctx = 0xFFFFFFFFu, st;
    st_ile3 it[3];
    int n = 0, k, depth;

    if (max < 2) return -1;
    names[n++][0] = '\0';
    st_copy(names[0], 32, "SYS$BATCH");
    /* SUBMIT resolves SYS$BATCH through logical names, at boot the system table's, in
       turn: follow it as far as it goes (9 levels, as OpenVMS does). */
    desc(&tab, "LNM$SYSTEM_TABLE", 16);
    for (depth = 0; depth < 9; depth++) {
        desc(&nam, batch, (unsigned short) strlen(batch));
        blen = 0;
        item(&it[0], LNM$_STRING, next, sizeof next - 1, &blen);
        item_end(&it[1]);
        if (!(sys$trnlnm(0, &tab, &nam, 0, it) & 1)) break;
        next[blen] = '\0';
        if (blen && next[blen - 1] == ':') next[--blen] = '\0';
        if (!blen || !strcmp(next, batch)) break;
        st_copy(batch, sizeof batch, next);
        if (n >= max) return -1;
        st_copy(names[n++], 32, batch);
    }
    /* And the execution queues it feeds, if it is generic. If that cannot be read,
       say so: the caller then refuses every stop rather than guess (fail closed). */
    item(&it[0], QUI$_SEARCH_NAME, batch, (unsigned short) strlen(batch), 0);
    item(&it[1], QUI$_GENERIC_TARGET, targets, sizeof targets, &tlen);
    item_end(&it[2]);
    st = qui(QUI$_DISPLAY_QUEUE, &ctx, it);
    qui(QUI$_CANCEL_OPERATION, &ctx, 0);
    if (st == JBC$_NOSUCHQUE || st == JBC$_NOMOREQUE) return n;   /* no such queue: nothing feeds */
    if (!(st & 1) || tlen >= sizeof targets) return -1;
    k = st_queue_target_list(targets, tlen, names + n, max - n);
    if (k < 0) return -1;
    return n + k;
}

/* ================================================================ misc */

long long st_plat_time(void) { return (long long) time(NULL); }

long long st_plat_now_ms(void) { return now_utc_ms(); }

void st_plat_sleep_ms(long long ms)
{
    /* LIB$WAIT reads VAX F_floating unless told the type (NOTES.md): 4 is IEEE S. */
    float secs;
    int type = 4;
    if (ms <= 0) return;
    secs = (float) ms / 1000.0f;
    lib$wait(&secs, 0, &type);
}

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
