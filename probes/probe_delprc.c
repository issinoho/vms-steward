/* probe_delprc.c - under a persona, may $DELPRC stop another process? (Phase 8b)

   Usage: probe_delprc <username> <priv,...|none> <pid-hex>

   Assumes <username>'s persona, enables the privileges given (GROUP, WORLD), and
   calls $DELPRC on <pid>, as STOP/ID does. Prints the answer, then whether the
   process still exists (by $GETJPI as the natural process, which sees everything
   here). Then reverts.

   Questions (PHASE8.md, 8b):
   - Does OpenVMS check the persona's UIC and GROUP/WORLD, not the process's (which
     here holds every privilege)? Without GROUP, another member's process must be
     refused.
   - What does it answer for a process the persona may not see, and for none?

   STOPS A PROCESS: run it only on a process started for the purpose (PHASE8.md). */
#include <stdlib.h>
#include <ctype.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static void enable(char *list)
{
    char *p;
    for (p = strtok(list, ","); p; p = strtok(0, ",")) {
        unsigned long long m = 0;
        unsigned int mask[2];
        char label[48], *q;
        for (q = p; *q; q++) *q = (char) toupper((unsigned char) *q);   /* argv is lowercased */
        if (!strcmp(p, "NONE")) continue;
        if (!strcmp(p, "GROUP")) m = PRV$M_GROUP;
        else if (!strcmp(p, "WORLD")) m = PRV$M_WORLD;
        if (!m) { printf("  unknown privilege %s\n", p); continue; }
        mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
        sprintf(label, "$SETPRV enable %s", p);
        report(label, sys$setprv(1, (void *) mask, 0, 0));
    }
}

static void exists(unsigned int pid, const char *when)
{
    unsigned int iosb[2], st, got = 0;
    ile3 it[2];
    ile3_set(&it[0], JPI$_PID, &got, 4, 0);
    ile3_end(&it[1]);
    st = sys$getjpiw(0, &pid, 0, it, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    printf("  %-34s %s\n", when, (st & 1) ? "still there" : msg(st));
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st, pid, i;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    struct dsc$descriptor_s d;

    if (argc < 4) { printf("usage: probe_delprc <username> <privs|none> <pid-hex>\n"); return 1; }
    pid = (unsigned int) strtoul(argv[3], 0, 16);
    printf("probe_delprc: %s, %s, target %08X\n", argv[1], argv[2], pid);
    exists(pid, "before");
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        enable(argv[2]);
        report("$DELPRC under the persona", sys$delprc(&pid, 0, 0));
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    for (i = 0; i < 2000000; i++) ;   /* a moment for the deletion to finish */
    exists(pid, "after");
    return 1;
}
