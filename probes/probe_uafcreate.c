/* probe_uafcreate.c - can we create and remove a user as AUTHORIZE ADD/COPY/REMOVE do?
   (Phase 4, D6)

   Usage:  probe_uafcreate CREATE <new> <template> <uic>    e.g. STEWARD_NEW DEFAULT [362,10]
           probe_uafcreate REMOVE <new>

   CHANGES SYSUAF AND RIGHTSLIST, ONLY FOR STEWARD_NEW AND STEWARD_COPY (approved by the
   user for Phase 4 testing, 2026-10-11). It refuses any other name, and refuses to
   CREATE over an existing account.

   CREATE: read the template's record (RMS keyed $GET, shared, no lock), copy it, set
   the username (keeping the template's tag byte), UIC and owner, clear the password
   hashes, login history and failure count, and $PUT it. Then set a random password,
   pre-expired, with $SETUAI (the system hashes it), and add the UIC identifier with
   $ADD_IDENT, as AUTHORIZE ADD does. The layout is UAFDEF's own struct, from
   SYS$LIB_C.TLB, not offsets written here.
   REMOVE: revoke everything the user holds ($FIND_HELD + $REM_HOLDER), remove the UIC
   identifier ($REM_IDENT), then the record (RMS keyed $FIND + $DELETE).

   Compare with AUTHORIZE SHOW <new> and SHOW <template> afterwards. */
#include <stdlib.h>
#include <time.h>
#include <rms.h>
#include <ssdef.h>
#include <uaidef.h>
#include <uafdef.h>
#include "probe_common.h"

static int allowed(const char *u) { return !strcmp(u, "STEWARD_NEW") || !strcmp(u, "STEWARD_COPY"); }

static void up(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; src[i] && i < n - 1; i++) dst[i] = (char) ((src[i] >= 'a' && src[i] <= 'z') ? src[i] - 32 : src[i]);
    dst[i] = '\0';
}

static unsigned int open_uaf(struct FAB *fab, struct RAB *rab, int write)
{
    unsigned int st;
    *fab = cc$rms_fab;
    *rab = cc$rms_rab;
    fab->fab$l_fna = "SYSUAF";           fab->fab$b_fns = 6;
    fab->fab$l_dna = "SYS$SYSTEM:.DAT";  fab->fab$b_dns = 15;
    fab->fab$b_fac = write ? (FAB$M_GET | FAB$M_PUT | FAB$M_DEL | FAB$M_UPD) : FAB$M_GET;
    fab->fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;
    st = sys$open(fab);
    report("$OPEN SYSUAF", st);
    if (!(st & 1)) return st;
    rab->rab$l_fab = fab;
    st = sys$connect(rab);
    if (!(st & 1)) { report("$CONNECT", st); sys$close(fab); }
    return st;
}

static unsigned int uic_parse(const char *s)
{
    unsigned int g = 0, m = 0;
    if (sscanf(s, "[%o,%o]", &g, &m) != 2) return 0;
    return (g << 16) | m;
}

int main(int argc, char **argv)
{
    char user[13], tmpl[13], key[32];
    struct FAB fab;
    struct RAB rab;
    static UAF rec;
    unsigned int st, uic;
    size_t n;

    if (argc < 3) { printf("usage: probe_uafcreate CREATE <new> <template> <uic> | REMOVE <new>\n"); return 1; }
    up(user, argv[2], sizeof user);
    if (!allowed(user)) { printf("probe_uafcreate: only STEWARD_NEW or STEWARD_COPY\n"); return 1; }
    memset(key, ' ', sizeof key);
    memcpy(key, user, strlen(user));
    printf("probe_uafcreate: sizeof(UAF) = %u (UAF$C_LENGTH %u, fixed part %u)\n",
           (unsigned) sizeof rec, (unsigned) UAF$C_LENGTH, (unsigned) UAF$C_FIXED);

    if (argv[1][0] == 'C' || argv[1][0] == 'c') {
        struct dsc$descriptor_s d, idd;
        char pw[33], owner[32];
        unsigned int ident = 0, never[2] = { 0xFFFFFFFFu, 0xFFFFFFFFu };
        ile3 it[3];
        if (argc != 5) { printf("usage: CREATE <new> <template> <uic>\n"); return 1; }
        up(tmpl, argv[3], sizeof tmpl);
        uic = uic_parse(argv[4]);
        if (!uic) { printf("probe_uafcreate: bad UIC %s\n", argv[4]); return 1; }
        if (!(open_uaf(&fab, &rab, 1) & 1)) return 1;
        /* the new name must not exist */
        rab.rab$b_rac = RAB$C_KEY; rab.rab$b_krf = 0; rab.rab$l_kbf = key; rab.rab$b_ksz = 32;
        rab.rab$l_rop = RAB$M_NLK | RAB$M_RRL;
        rab.rab$l_ubf = (char *) &rec; rab.rab$w_usz = sizeof rec;
        st = sys$get(&rab);
        if (st & 1) { printf("probe_uafcreate: %s already exists; not touching it\n", user); sys$close(&fab); return 1; }
        /* the template */
        memset(key, ' ', sizeof key);
        memcpy(key, tmpl, strlen(tmpl));
        st = sys$get(&rab);
        report("$GET template", st);
        if (!(st & 1)) { sys$close(&fab); return 1; }
        printf("  template %.12s: record %u bytes, type %u version %u, usrdatoff %u, tag %%X%02X\n",
               tmpl, rab.rab$w_rsz, rec.uaf$b_rtype, rec.uaf$b_version, rec.uaf$w_usrdatoff,
               (unsigned char) rec.uaf$t_username_tag);
        /* the new record */
        memset(rec.uaf$t_username, ' ', 31);                  /* the tag byte [31] is kept */
        memcpy(rec.uaf$t_username, user, strlen(user));
        rec.uaf$l_uic = uic;
        n = strlen("steward probe_uafcreate");
        memset(owner, ' ', sizeof owner);
        owner[0] = (char) n;
        memcpy(owner + 1, "steward probe_uafcreate", n);
        memcpy(rec.uaf$t_owner, owner, sizeof owner);
        rec.uaf$q_pwd = 0;
        rec.uaf$q_pwd2 = 0;
        rec.uaf$w_logfails = 0;
        rec.uaf$w_salt = 0;
        rec.uaf$q_pwd_date = 0;
        rec.uaf$q_pwd2_date = 0;
        rec.uaf$q_lastlogin_i = 0;
        rec.uaf$q_lastlogin_n = 0;
        rab.rab$b_rac = RAB$C_KEY;
        rab.rab$l_rbf = (char *) &rec;
        rab.rab$w_rsz = rab.rab$w_rsz;                         /* the template's length */
        st = sys$put(&rab);
        report("$PUT new record", st);
        sys$close(&fab);
        if (!(st & 1)) return 1;
        /* a password nobody knows, pre-expired: the system hashes it */
        srand((unsigned) time(NULL));
        for (n = 0; n < 24; n++) pw[n] = (char) ('a' + rand() % 26);
        pw[24] = '\0';
        desc_set(&d, user, (unsigned short) strlen(user));
        ile3_set(&it[0], UAI$_PASSWORD, pw, 24, 0);
        ile3_end(&it[1]);
        report("$SETUAI PASSWORD", sys$setuai(0, 0, &d, it, 0, 0, 0));
        ile3_set(&it[0], UAI$_PWD_DATE, never, 8, 0);
        report("$SETUAI PWD_DATE pre-expired", sys$setuai(0, 0, &d, it, 0, 0, 0));
        memset(pw, 0, sizeof pw);
        desc_set(&idd, user, (unsigned short) strlen(user));
        report("$ADD_IDENT UIC identifier", sys$add_ident(&idd, uic, 0, &ident));
        return 1;
    }

    /* REMOVE */
    {
        struct dsc$descriptor_s d;
        unsigned int id = 0, attrib = 0, holder[2], ctx = 0, held[64], nheld = 0, i;
        ile3 it[2];
        uic = 0;
        desc_set(&d, user, (unsigned short) strlen(user));
        ile3_set(&it[0], UAI$_UIC, &uic, 4, 0);
        ile3_end(&it[1]);
        st = sys$getuai(0, 0, &d, it, 0, 0, 0);
        report("$GETUAI UIC", st);
        if (!(st & 1)) return 1;
        holder[0] = uic; holder[1] = 0;
        while (nheld < 64 && (sys$find_held((void *) holder, &id, &attrib, &ctx) & 1)) held[nheld++] = id;
        sys$finish_rdb(&ctx);
        for (i = 0; i < nheld; i++) report("$REM_HOLDER", sys$rem_holder(held[i], (void *) holder));
        report("$REM_IDENT UIC identifier", sys$rem_ident(uic));
        if (!(open_uaf(&fab, &rab, 1) & 1)) return 1;
        rab.rab$b_rac = RAB$C_KEY; rab.rab$b_krf = 0; rab.rab$l_kbf = key; rab.rab$b_ksz = 32;
        rab.rab$l_ubf = (char *) &rec; rab.rab$w_usz = sizeof rec;
        rab.rab$l_rop = 0;                                     /* lock it: we are deleting */
        st = sys$find(&rab);
        report("$FIND record", st);
        if (st & 1) report("$DELETE record", sys$delete(&rab));
        sys$close(&fab);
        return 1;
    }
}
