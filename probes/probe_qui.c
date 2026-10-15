/* probe_qui.c - under a persona, which queues and jobs does $GETQUI show? (Phase 9)

   Usage: probe_qui <username|-> [priv,...|none]
          probe_qui targets <generic-queue>      (QUI$_GENERIC_TARGET's buffer, dumped)

   Walks every queue (QUI$_DISPLAY_QUEUE, "*") and, in each, every job it is given
   (QUI$_DISPLAY_JOB with QUI$M_SEARCH_ALL_JOBS), printing queue name, kind and status,
   and each job's entry, name, username and status, with any refusal. With a username,
   under that persona with the privileges given (OPER, READALL, SYSPRV, WORLD...);
   with "-", as this process, for comparison.

   Question (PHASE9.md): $GETQUI asks the queue manager, another process. Does it
   judge the request by the persona (its UIC, rights and privileges) or by this
   process (which holds every privilege)? Run it as STEWARD_TEST with a job of its own
   and one of someone else's in a queue: if the persona counts, the other's job must
   be hidden or refused, as SHOW QUEUE/ALL does at a terminal.
   Changes nothing. */
#include <stdlib.h>
#include <ctype.h>
#include <ssdef.h>
#include <prvdef.h>
#include <quidef.h>
#include <jbcmsgdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static unsigned long long priv_mask(const char *name)
{
    if (!strcmp(name, "OPER")) return PRV$M_OPER;
    if (!strcmp(name, "READALL")) return PRV$M_READALL;
    if (!strcmp(name, "SYSPRV")) return PRV$M_SYSPRV;
    if (!strcmp(name, "WORLD")) return PRV$M_WORLD;
    if (!strcmp(name, "GROUP")) return PRV$M_GROUP;
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
        if (!strcmp(p, "NONE")) continue;
        if (!(m = priv_mask(p))) { printf("  unknown privilege %s\n", p); continue; }
        mask[0] = (unsigned int) m; mask[1] = (unsigned int) (m >> 32);
        sprintf(label, "$SETPRV enable %s", p);
        report(label, sys$setprv(1, (void *) mask, 0, 0));
    }
}

static void walk(void)
{
    static char search[] = "*";
    unsigned int ctx = 0xFFFFFFFFu, iosb[2], st, flags, status, nq = 0, nj;
    unsigned int all = QUI$M_SEARCH_ALL_JOBS, entry, jstatus;
    char qname[32], jname[40], user[13];
    unsigned short ql, jl, ul;
    ile3 qi[5], ji[6];
    ile3_set(&qi[0], QUI$_SEARCH_NAME, search, 1, 0);
    ile3_set(&qi[1], QUI$_QUEUE_NAME, qname, sizeof qname - 1, &ql);
    ile3_set(&qi[2], QUI$_QUEUE_FLAGS, &flags, 4, 0);
    ile3_set(&qi[3], QUI$_QUEUE_STATUS, &status, 4, 0);
    ile3_end(&qi[4]);
    ile3_set(&ji[0], QUI$_SEARCH_FLAGS, &all, 4, 0);
    ile3_set(&ji[1], QUI$_ENTRY_NUMBER, &entry, 4, 0);
    ile3_set(&ji[2], QUI$_JOB_NAME, jname, sizeof jname - 1, &jl);
    ile3_set(&ji[3], QUI$_USERNAME, user, sizeof user - 1, &ul);
    ile3_set(&ji[4], QUI$_JOB_STATUS, &jstatus, 4, 0);
    ile3_end(&ji[5]);
    for (;;) {
        ql = 0; flags = status = 0;
        st = sys$getquiw(0, QUI$_DISPLAY_QUEUE, &ctx, qi, iosb, 0, 0);
        if (st & 1) st = iosb[0];
        if (st == JBC$_NOMOREQUE) break;
        if (!(st & 1)) { printf("  queue walk: %s\n", msg(st)); break; }
        qname[ql] = '\0';
        nq++;
        printf("  %-20s %s%s\n", qname, (flags & QUI$M_QUEUE_BATCH) ? "batch" : "output",
               (status & QUI$M_QUEUE_STOPPED) ? ", stopped" : "");
        for (nj = 0; nj < 1000; nj++) {   /* bounded: a first run looped on NOSUCHJOB */
            jl = ul = 0; entry = jstatus = 0;
            st = sys$getquiw(0, QUI$_DISPLAY_JOB, &ctx, ji, iosb, 0, 0);
            if (st & 1) st = iosb[0];
            if (st == JBC$_NOMOREJOB) break;
            if (!(st & 1)) { printf("      job: %s\n", msg(st)); break; }
            jname[jl] = '\0'; user[ul] = '\0'; rtrim(user);
            printf("      %5u %-20s %-12s status %%X%08X\n", entry, jname, user, jstatus);
        }
    }
    printf("  %u queues\n", nq);
    sys$getquiw(0, QUI$_CANCEL_OPERATION, &ctx, 0, iosb, 0, 0);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    struct dsc$descriptor_s d;

    if (argc < 2) { printf("usage: probe_qui <username|-> [privs|none]\n"); return 1; }
    printf("probe_qui: %s %s\n", argv[1], argc > 2 ? argv[2] : "");
    if (!strcmp(argv[1], "-")) { walk(); return 1; }
    if (!strcmp(argv[1], "targets") && argc > 2) {   /* the layout of QUI$_GENERIC_TARGET */
        unsigned char buf[512];
        char name[32];
        unsigned short len = 0;
        unsigned int ctx = 0xFFFFFFFFu, iosb[2], k;
        ile3 it[3];
        for (k = 0; argv[2][k] && k < 31; k++) name[k] = (char) toupper((unsigned char) argv[2][k]);
        name[k] = '\0';
        memset(buf, 0xAA, sizeof buf);
        ile3_set(&it[0], QUI$_SEARCH_NAME, name, (unsigned short) strlen(name), 0);
        ile3_set(&it[1], QUI$_GENERIC_TARGET, buf, sizeof buf, &len);
        ile3_end(&it[2]);
        st = sys$getquiw(0, QUI$_DISPLAY_QUEUE, &ctx, it, iosb, 0, 0);
        if (st & 1) st = iosb[0];
        printf("  %s, %u bytes:", msg(st), len);
        for (k = 0; k < (unsigned) len + 4 && k < sizeof buf; k++) printf("%s%02X", k % 32 ? " " : "\n   ", buf[k]);
        printf("\n");
        return 1;
    }
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        if (argc > 2) enable(argv[2]);
        walk();
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    return 1;
}
