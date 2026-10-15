/* probe_hold.c - hold a persona for a while, so another process can look (Phase 8b).

   Usage: probe_hold <username> [seconds]

   Assumes <username>'s persona, prints this process's PID, waits (default 60 s),
   then reverts. Meanwhile, from another session, F$GETJPI or probe_jpi on that PID
   shows what OpenVMS reports for a process that holds a persona: whose username and
   UIC? A Steward pool worker serving a request is such a process (the Phase 8 review).
   Changes nothing. */
#include <stdlib.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include <lib$routines.h>
#include <libwaitdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st, pid = 0, iosb[2];
    unsigned int imp[2] = { PRV$M_DETACH | PRV$M_SYSPRV, 0 }, ftype = LIB$K_IEEE_S;   /* SYSPRV: $PERSONA_CREATE */
    float secs = argc > 2 ? (float) atoi(argv[2]) : 60.0f;   /* IEEE: NOTES.md, LIB$WAIT */
    struct dsc$descriptor_s d;
    ile3 it[2];

    if (argc < 2) { printf("usage: probe_hold <username> [seconds]\n"); return 1; }
    ile3_set(&it[0], JPI$_PID, &pid, 4, 0);
    ile3_end(&it[1]);
    sys$getjpiw(0, 0, 0, it, iosb, 0, 0);
    report("$SETPRV IMPERSONATE, SYSPRV", sys$setprv(1, (void *) imp, 0, 0));
    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    report("$PERSONA_ASSUME", sys$persona_assume(&persona, 0, 0, 0));
    printf("HOLDING %08X as %s for %.0f s\n", pid, argv[1], secs);
    fflush(stdout);
    lib$wait(&secs, 0, &ftype);
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    return 1;
}
