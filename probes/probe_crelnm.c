/* probe_crelnm.c - under a persona, what do $CRELNM and $DELLNM do? (Phase 7b)

   Usage: probe_crelnm <username> <table> <name> [priv,priv,...]

   Assumes <username>'s persona, enables the privileges given (as SET
   PROCESS/PRIVILEGE would: GRPPRV, GRPNAM, SYSNAM, SYSPRV), and in <table>:
   - for each of user, supervisor and executive mode: defines <name> with $CRELNM,
     reads it back with $TRNLNM at that mode (did it get the mode asked for, or a
     less privileged one?), and defines it again (SUPERSEDE?);
   - deassigns it with $DELLNM at each mode, executive first;
   - reads back what is left.
   Also prints what LNM$GROUP translates to under the persona (the service's group or
   the persona's?). Then reverts and checks the revert.

   Questions (PHASE7.md, 7b):
   - Does OpenVMS check the persona's privileges and UIC, not the process's? Run it
     as a username without GRPNAM/SYSNAM against a table the process could write: it
     must fail.
   - Without SYSNAM, is a request for executive mode refused, or quietly made user
     mode (which the API would then have to check)?
   - Is GRPPRV (system access to the group's objects) enough for the group table?

   WRITES LOGICAL NAMES in <table>, and deassigns them at the end: run it only on a
   table and name the user has agreed to. Never logs a password (it has none). */
#include <stdlib.h>
#include <ctype.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include <lnmdef.h>
#include <psldef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static const char *const mode_name[] = { "kernel", "exec", "super", "user" };

static void curpriv(const char *when)
{
    unsigned int priv[2] = {0, 0}, iosb[2], st;
    char user[13]; unsigned short ulen = 0;
    ile3 items[3];
    ile3_set(&items[0], JPI$_USERNAME, user, 12, &ulen);
    ile3_set(&items[1], JPI$_CURPRIV, priv, 8, 0);
    ile3_end(&items[2]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    user[ulen] = '\0'; rtrim(user);
    printf("    %-10s %s curpriv %%X%08X%08X%s\n", when, user, priv[1], priv[0],
           (st & 1) ? "" : msg(st));
}

/* PRV$M_ masks above bit 31 (GRPPRV) are 64-bit constants: carry the quadword. */
static unsigned long long priv_mask(const char *name)
{
    if (!strcmp(name, "GRPPRV")) return PRV$M_GRPPRV;
    if (!strcmp(name, "GRPNAM")) return PRV$M_GRPNAM;
    if (!strcmp(name, "SYSNAM")) return PRV$M_SYSNAM;
    if (!strcmp(name, "SYSPRV")) return PRV$M_SYSPRV;
    return 0;
}

static void enable(char *list)
{
    char *p;
    for (p = strtok(list, ","); p; p = strtok(0, ",")) {
        unsigned long long m;
        unsigned int mask[2];
        char label[48], *q;
        for (q = p; *q; q++) if (*q >= 'a' && *q <= 'z') *q -= 32;   /* argv is lowercased */
        m = priv_mask(p);
        if (!m) { printf("  unknown privilege %s\n", p); continue; }
        mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
        sprintf(label, "$SETPRV enable %s", p);
        report(label, sys$setprv(1, (void *) mask, 0, 0));
    }
}

/* What <name> translates to in <tab>, ignoring names less privileged than <mode>. */
static void readback(struct dsc$descriptor_s *tab, struct dsc$descriptor_s *nam,
                     unsigned char mode, const char *when)
{
    char string[256]; unsigned short slen = 0;
    unsigned char acmode = 9;
    unsigned int st;
    ile3 it[3];
    ile3_set(&it[0], LNM$_STRING, string, 255, &slen);
    ile3_set(&it[1], LNM$_ACMODE, &acmode, 1, 0);
    ile3_end(&it[2]);
    st = sys$trnlnm(0, tab, nam, &mode, it);
    string[slen] = '\0';
    if (st & 1)
        printf("    %-24s at %-6s or inner: \"%s\", %s mode\n", when, mode_name[mode], string,
               acmode < 4 ? mode_name[acmode] : "?");
    else
        printf("    %-24s at %-6s or inner: %s\n", when, mode_name[mode], msg(st));
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    unsigned char mode;
    struct dsc$descriptor_s d, tab, nam, pdir, grp;
    char table[32], name[64], value[32], label[64], grpout[64];
    unsigned short glen = 0;
    ile3 it[2];
    int i;

    if (argc < 4) { printf("usage: probe_crelnm <username> <table> <name> [privs]\n"); return 1; }
    /* The C RTL lowercases argv; table and logical names here are uppercase. */
    for (i = 0; argv[2][i] && i < 31; i++) table[i] = (char) toupper((unsigned char) argv[2][i]);
    table[i] = '\0';
    for (i = 0; argv[3][i] && i < 63; i++) name[i] = (char) toupper((unsigned char) argv[3][i]);
    name[i] = '\0';
    printf("probe_crelnm: %s in %s, name %s\n", argv[1], table, name);
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    curpriv("natural");

    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        if (argc > 4) enable(argv[4]);
        curpriv("assumed");

        desc_set(&pdir, "LNM$PROCESS_DIRECTORY", 21);
        desc_set(&grp, "LNM$GROUP", 9);
        ile3_set(&it[0], LNM$_STRING, grpout, 63, &glen);
        ile3_end(&it[1]);
        st = sys$trnlnm(0, &pdir, &grp, 0, it);
        grpout[(st & 1) ? glen : 0] = '\0';
        printf("  LNM$GROUP under the persona: \"%s\" %s\n", grpout, msg(st));

        desc_set(&tab, table, (unsigned short) strlen(table));
        desc_set(&nam, name, (unsigned short) strlen(name));
        for (mode = PSL$C_USER; mode >= PSL$C_EXEC; mode--) {
            sprintf(value, "PROBE_%s", mode_name[mode]);
            ile3_set(&it[0], LNM$_STRING, value, (unsigned short) strlen(value), 0);
            ile3_end(&it[1]);
            sprintf(label, "$CRELNM %s", mode_name[mode]);
            report(label, sys$crelnm(0, &tab, &nam, &mode, it));
            readback(&tab, &nam, mode, "then");
            sprintf(label, "$CRELNM %s again", mode_name[mode]);
            report(label, sys$crelnm(0, &tab, &nam, &mode, it));
        }
        for (mode = PSL$C_EXEC; mode <= PSL$C_USER; mode++) {
            sprintf(label, "$DELLNM %s", mode_name[mode]);
            report(label, sys$dellnm(&tab, &nam, &mode));
            readback(&tab, &nam, PSL$C_USER, "left");
        }
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    curpriv("reverted");
    return 1;
}
