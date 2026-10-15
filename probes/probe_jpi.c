/* probe_jpi.c - under a persona, which processes does $GETJPI show? (Phase 8, read-only)

   Usage: probe_jpi <username> [priv,priv,...] [pid-hex]

   Assumes <username>'s persona, enables the privileges given (GROUP, WORLD, SYSPRV,
   ...), and walks the system with wildcard $GETJPI (pidadr -1), printing each process
   it is given: PID, username, process name, UIC, state, image. Then it asks for one
   process by PID (default: this process's own, the natural one), and reports what
   came back. Then reverts and checks the revert.

   Questions (PHASE8.md):
   - Is the wildcard filtered by the persona's UIC and its GROUP/WORLD, or by the
     process's own (which here holds every privilege)?
   - What does a PID the persona may not see answer: NOPRIV, NONEXPR, or nothing?
   - How long does a full walk take?
   Changes nothing. */
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <ssdef.h>
#include <jpidef.h>
#include <prvdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static unsigned long long priv_mask(const char *name)
{
    if (!strcmp(name, "GROUP")) return PRV$M_GROUP;
    if (!strcmp(name, "WORLD")) return PRV$M_WORLD;
    if (!strcmp(name, "SYSPRV")) return PRV$M_SYSPRV;
    if (!strcmp(name, "GRPPRV")) return PRV$M_GRPPRV;
    if (!strcmp(name, "READALL")) return PRV$M_READALL;
    return 0;
}

static void enable(char *list)
{
    char *p;
    for (p = strtok(list, ","); p; p = strtok(0, ",")) {
        unsigned long long m;
        unsigned int mask[2];
        char label[48], *q;
        for (q = p; *q; q++) *q = (char) toupper((unsigned char) *q);   /* argv is lowercased */
        if (!strcmp(p, "-")) continue;
        m = priv_mask(p);
        if (!m) { printf("  unknown privilege %s\n", p); continue; }
        mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
        sprintf(label, "$SETPRV enable %s", p);
        report(label, sys$setprv(1, (void *) mask, 0, 0));
    }
}

/* One process's line; returns the $GETJPI status. pidadr -1 walks the system. */
static unsigned int one(unsigned int *pidadr, int print)
{
    unsigned int pid = 0, uic = 0, state = 0, iosb[2], st;
    char user[13], prc[16], img[256];
    unsigned short ulen = 0, plen = 0, ilen = 0;
    ile3 it[7];
    ile3_set(&it[0], JPI$_PID, &pid, 4, 0);
    ile3_set(&it[1], JPI$_USERNAME, user, 12, &ulen);
    ile3_set(&it[2], JPI$_PRCNAM, prc, 15, &plen);
    ile3_set(&it[3], JPI$_UIC, &uic, 4, 0);
    ile3_set(&it[4], JPI$_STATE, &state, 4, 0);
    ile3_set(&it[5], JPI$_IMAGNAME, img, 255, &ilen);
    ile3_end(&it[6]);
    st = sys$getjpiw(0, pidadr, 0, it, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    if ((st & 1) && print) {
        user[ulen] = '\0'; rtrim(user);
        prc[plen] = '\0';
        img[ilen] = '\0';
        printf("    %08X %-12s %-15s [%o,%o] state %2u %s\n", pid, user, prc, uic >> 16, uic & 0xFFFF,
               state, ilen ? img : "");
    }
    return st;
}

static void walk(const char *when)
{
    unsigned int ctx = 0xFFFFFFFF, st, n = 0;
    clock_t t0 = clock();
    printf("  wildcard walk (%s):\n", when);
    for (;;) {
        st = one(&ctx, 1);
        if (st == SS$_NOMOREPROC) break;
        if (st == SS$_NOPRIV || st == SS$_SUSPENDED) { printf("    (skipped: %s)\n", msg(st)); continue; }
        if (!(st & 1)) { printf("    stopped: %s\n", msg(st)); break; }
        n++;
    }
    printf("  %u processes, %.2f s CPU\n", n, (double) (clock() - t0) / CLOCKS_PER_SEC);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st, self = 0, target, iosb[2];
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    struct dsc$descriptor_s d;
    ile3 it[2];

    if (argc < 2) { printf("usage: probe_jpi <username> [privs|-] [pid-hex]\n"); return 1; }
    ile3_set(&it[0], JPI$_PID, &self, 4, 0);
    ile3_end(&it[1]);
    sys$getjpiw(0, 0, 0, it, iosb, 0, 0);
    target = argc > 3 ? (unsigned int) strtoul(argv[3], 0, 16) : self;
    printf("probe_jpi: %s, this process %08X, target %08X\n", argv[1], self, target);
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));

    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        if (argc > 2) enable(argv[2]);
        walk("under the persona");
        printf("  one PID under the persona:\n");
        report("$GETJPI target", one(&target, 1));
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    return 1;
}
