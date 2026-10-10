/* probe_persona.c - does a per-request persona make the OS check the caller's rights? (read-only)

   Usage: probe_persona <username>

   With IMPERSONATE (enabled here if authorized), $PERSONA_CREATE for <username>, assume
   it, and then do what a request would: $GETJPI, $GETUAI on SYSTEM, and $OPEN SYSUAF.
   Revert to the natural persona and delete it, then check that the revert happened.
   No password is involved: the login check is SYS$ACM's job (probe_acm).

   Run it with an unprivileged username: if D2 holds, $GETUAI SYSTEM and $OPEN SYSUAF
   fail with NOPRIV under the persona and succeed again after the revert. Changes
   nothing. */
#include <stdlib.h>
#include <rms.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include <uaidef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1      /* the process's own persona (<issdef.h>) */
#endif

static void whoami(const char *when)
{
    char user[13]; unsigned short ulen = 0; unsigned int priv[2] = {0, 0}, iosb[2], st;
    ile3 items[3];
    ile3_set(&items[0], JPI$_USERNAME, user, 12, &ulen);
    ile3_set(&items[1], JPI$_CURPRIV, priv, 8, 0);
    ile3_end(&items[2]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    user[ulen] = '\0'; rtrim(user);
    printf("  [%s] $GETJPI username \"%s\" curpriv %%X%08X%08X (%s)\n",
           when, user, priv[1], priv[0], msg(st));
}

static void try_access(const char *when)
{
    struct FAB fab = cc$rms_fab;
    struct dsc$descriptor_s d;
    unsigned int uic = 0, st;
    ile3 items[2];
    char label[64];

    desc_set(&d, "SYSTEM", 6);
    ile3_set(&items[0], UAI$_UIC, &uic, 4, 0); ile3_end(&items[1]);
    st = sys$getuai(0, 0, &d, items, 0, 0, 0);
    sprintf(label, "[%s] $GETUAI SYSTEM", when); report(label, st);

    fab.fab$l_fna = "SYSUAF"; fab.fab$b_fns = 6;
    fab.fab$l_dna = "SYS$SYSTEM:.DAT"; fab.fab$b_dns = 15;
    fab.fab$b_fac = FAB$M_GET;
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;
    st = sys$open(&fab);
    sprintf(label, "[%s] $OPEN SYSUAF", when); report(label, st);
    if (st & 1) sys$close(&fab);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };   /* IMPERSONATE is the old DETACH bit */
    struct dsc$descriptor_s d;

    if (argc < 2) { printf("usage: probe_persona <username>\n"); return 1; }
    printf("probe_persona: %s\n", argv[1]);

    st = sys$setprv(1, (void *) imp, 0, 0);
    report("$SETPRV IMPERSONATE", st);
    whoami("natural");
    try_access("natural");

    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;

    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        whoami("persona");
        try_access("persona");
    }

    st = sys$persona_assume(&natural, 0, 0, 0);
    report("$PERSONA_ASSUME natural", st);
    st = sys$persona_delete(&persona);
    report("$PERSONA_DELETE", st);
    whoami("reverted");
    try_access("reverted");
    return 1;
}
