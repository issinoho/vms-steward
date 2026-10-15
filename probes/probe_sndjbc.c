/* probe_sndjbc.c - under a persona, which job and queue changes does $SNDJBC allow?
   (Phase 9b)

   Usage: probe_sndjbc <username> <priv,...|none> <op> <entry|queue>
     op: hold, release, delete (a job by entry number), stop, start (a queue)

   Assumes <username>'s persona, enables the privileges given (SYSPRV, OPER, WORLD,
   GROUP), and asks the queue manager, as SET ENTRY/HOLD and /RELEASE, DELETE/ENTRY,
   STOP/QUEUE and START/QUEUE do. Prints the answer. Then reverts.

   Question (PHASE9.md): does the queue manager judge $SNDJBC by the persona, as it
   does $GETQUI, and not by this process (which holds every privilege)?

   CHANGES A JOB OR A QUEUE: run it only on jobs and queues set up for the purpose. */
#include <stdlib.h>
#include <ctype.h>
#include <ssdef.h>
#include <prvdef.h>
#include <sjcdef.h>
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
        if (!strcmp(p, "SYSPRV")) m = PRV$M_SYSPRV;
        else if (!strcmp(p, "OPER")) m = PRV$M_OPER;
        else if (!strcmp(p, "WORLD")) m = PRV$M_WORLD;
        else if (!strcmp(p, "GROUP")) m = PRV$M_GROUP;
        if (!m) { printf("  unknown privilege %s\n", p); continue; }
        mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
        sprintf(label, "$SETPRV enable %s", p);
        report(label, sys$setprv(1, (void *) mask, 0, 0));
    }
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st, iosb[2] = { 0, 0 }, entry = 0;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    unsigned short func = 0;
    char queue[32] = "", label[64], *q;
    struct dsc$descriptor_s d;
    ile3 it[3];
    int i;

    if (argc < 5) { printf("usage: probe_sndjbc <username> <privs|none> <op> <entry|queue>\n"); return 1; }
    if (!strcmp(argv[3], "hold") || !strcmp(argv[3], "release")) {
        func = SJC$_ALTER_JOB;
        entry = (unsigned int) atoi(argv[4]);
        ile3_set(&it[0], SJC$_ENTRY_NUMBER, &entry, 4, 0);
        ile3_set(&it[1], !strcmp(argv[3], "hold") ? SJC$_HOLD : SJC$_NO_HOLD, 0, 0, 0);
        ile3_end(&it[2]);
    } else if (!strcmp(argv[3], "delete")) {
        func = SJC$_DELETE_JOB;
        entry = (unsigned int) atoi(argv[4]);
        ile3_set(&it[0], SJC$_ENTRY_NUMBER, &entry, 4, 0);
        ile3_end(&it[1]);
    } else if (!strcmp(argv[3], "stop") || !strcmp(argv[3], "start")) {
        func = !strcmp(argv[3], "stop") ? SJC$_STOP_QUEUE : SJC$_START_QUEUE;
        for (i = 0, q = argv[4]; *q && i < 31; q++) queue[i++] = (char) toupper((unsigned char) *q);
        queue[i] = '\0';
        ile3_set(&it[0], SJC$_QUEUE, queue, (unsigned short) strlen(queue), 0);
        ile3_end(&it[1]);
    } else { printf("unknown op %s\n", argv[3]); return 1; }

    printf("probe_sndjbc: %s, %s, %s %s\n", argv[1], argv[2], argv[3], argv[4]);
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        enable(argv[2]);
        st = sys$sndjbcw(0, func, 0, it, (void *) iosb, 0, 0);
        if (st & 1) st = iosb[0];
        sprintf(label, "$SNDJBC %s", argv[3]);
        report(label, st);
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    return 1;
}
