/* probe_setprv.c - under a persona, which privileges can $SETPRV enable? (read-only)

   Usage: probe_setprv <username>

   Assumes <username>'s persona and tries to enable, one at a time, NETMBX (normally
   authorized and default), GRPPRV and SYSPRV, printing the $SETPRV status and the
   resulting current privileges after each, then reverts.

   Two questions:
   - Is the persona's authorized mask what limits $SETPRV, or does the process's own
     authorized mask (or its SETPRV privilege) leak through? With an unprivileged
     username, SYSPRV must come back NOTALLPRIV, or D2 is broken.
   - Can a persona enable a privilege that is authorized but not default, the way
     SET PROCESS/PRIVILEGE does? That needs a username with such a privilege.
   Changes nothing outside this process. */
#include <stdlib.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static void curpriv(const char *when)
{
    unsigned int priv[2] = {0, 0}, auth[2] = {0, 0}, iosb[2], st;
    ile3 items[3];
    ile3_set(&items[0], JPI$_CURPRIV, priv, 8, 0);
    ile3_set(&items[1], JPI$_AUTHPRIV, auth, 8, 0);
    ile3_end(&items[2]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    printf("    %-10s curpriv %%X%08X%08X authpriv %%X%08X%08X%s\n", when,
           priv[1], priv[0], auth[1], auth[0], (st & 1) ? "" : msg(st));
}

/* PRV$M_ masks for privileges 32-63 (GRPPRV is 0x400000000) are 64-bit constants.
   Stored in an unsigned int they become 0, and $SETPRV of an empty mask succeeds,
   so the whole quadword must be carried. */
static void try_enable(const char *name, unsigned long long m)
{
    unsigned int mask[2]; char label[48];
    mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
    sprintf(label, "$SETPRV enable %s", name);
    report(label, sys$setprv(1, (void *) mask, 0, 0));
    curpriv(name);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    struct dsc$descriptor_s d;

    if (argc < 2) { printf("usage: probe_setprv <username>\n"); return 1; }
    printf("probe_setprv: %s\n", argv[1]);
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    curpriv("natural");

    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        curpriv("assumed");
        try_enable("NETMBX", PRV$M_NETMBX);
        try_enable("GRPPRV", PRV$M_GRPPRV);
        try_enable("SYSPRV", PRV$M_SYSPRV);
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    curpriv("reverted");
    return 1;
}
