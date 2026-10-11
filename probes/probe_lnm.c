/* probe_lnm.c - how can Steward list logical names, as the viewer? (Phase 7, read-only)

   Usage: probe_lnm <username> [table]          (default LNM$SYSTEM_TABLE)

   No system service lists the names in a table: $TRNLNM translates one name you
   already know, and STARLET exports nothing that enumerates (checked 2026-10-11).
   SHOW LOGICAL can, because DCL calls internal routines. So: does a subprocess spawned
   while a persona is assumed run as that persona? If it does, Steward can run SHOW
   LOGICAL as the viewer and OpenVMS decides what they see (D2).

   With IMPERSONATE (and SYSPRV for $PERSONA_CREATE, as in the service), it creates
   and assumes <username>'s persona, then LIB$SPAWNs a subprocess that shows who it is
   and lists the table, with output to a file. It times the spawn, reverts, and spawns
   once more as the natural persona for comparison. Changes nothing. */
#include <stdlib.h>
#include <time.h>
#include <ssdef.h>
#include <prvdef.h>
#include <jpidef.h>
#include <dvidef.h>
#include <iodef.h>
#include <lib$routines.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static void spawn(const char *label, const char *table)
{
    char cmd[512];
    struct dsc$descriptor_s c, out;
    unsigned int st, status = 0;
    clock_t t0;
    static const char outname[] = "SYS$SCRATCH:PROBE_LNM.OUT";
    snprintf(cmd, sizeof cmd,
             "PIPE WRITE SYS$OUTPUT \"user=\", F$EDIT(F$GETJPI(\"\",\"USERNAME\"),\"TRIM\"), "
             "\" uic=\", F$GETJPI(\"\",\"UIC\"), \" curpriv=\", F$GETJPI(\"\",\"CURPRIV\") ; "
             "SHOW LOGICAL/FULL/TABLE=%s * ; WRITE SYS$OUTPUT \"group table: \", F$TRNLNM(\"LNM$GROUP\",\"LNM$PROCESS_DIRECTORY\")",
             table);
    desc_set(&c, cmd, (unsigned short) strlen(cmd));
    desc_set(&out, outname, (unsigned short) (sizeof outname - 1));
    t0 = clock();
    st = lib$spawn(&c, 0, &out, 0, 0, 0, &status);
    printf("  [%s] LIB$SPAWN %s, completion %%X%08X, %.0f ms CPU\n", label, msg(st), status,
           1000.0 * (double) (clock() - t0) / CLOCKS_PER_SEC);
    {
        FILE *f = fopen(outname, "r");
        char line[512];
        int n = 0, names = 0;
        if (!f) { printf("  [%s] no output file\n", label); return; }
        while (fgets(line, sizeof line, f)) {
            if (line[0] == ' ' && line[1] == ' ' && line[2] == '"') names++;
            if (n++ < 8 || !strncmp(line, "user=", 5) || !strncmp(line, "group table", 11)) printf("    | %s", line);
        }
        fclose(f);
        printf("  [%s] %d lines, %d names\n", label, n, names);
        remove(outname);
    }
}

/* What LIB$SPAWN does, by hand: commands in through one mailbox, output back through
   another, and LOGINOUT as a subprocess running DCL on them. $CREPRC while a persona
   is assumed gives the subprocess that persona (seen in accounting, 2026-10-11). */
/* D14 as designed: a detached LOGINOUT on a fixed procedure (vms/steward_lnm.com),
   told its two mailboxes through its process name, given only data. */
static void lnm_run(const char *proc, const char *table, const char *pattern, const char *log)
{
    unsigned short reqchan = 0, repchan = 0, iosb[4], len;
    char reqname[64] = "", repname[64] = "", prc[16], buf[1100];
    unsigned int st, pid = 0, jiosb[2], ieee_s = 4;
    struct dsc$descriptor_s img, in, nl, pn;
    ile3 it[2];
    int lines = 0, names = 0, idle = 0, done = 0;
    float tick = 0.01f;
    unsigned int t0[2], t1[2];

    sys$gettim((void *) t0);
    /* owner (the persona) only: system and owner may read and write, group and world nothing */
    st = sys$crembx(0, &reqchan, 512, 2048, 0xFF00, 0, 0, 0, 0);
    if (st & 1) st = sys$crembx(0, &repchan, 1024, 65000, 0xFF00, 0, 0, 0, 0);
    report("$CREMBX request and reply (S,O only)", st);
    ile3_set(&it[0], DVI$_UNIT, &st, 4, 0); ile3_end(&it[1]);
    {
        unsigned int u1 = 0, u2 = 0;
        ile3_set(&it[0], DVI$_UNIT, &u1, 4, 0);
        sys$getdviw(0, reqchan, 0, it, (void *) jiosb, 0, 0, 0);
        ile3_set(&it[0], DVI$_UNIT, &u2, 4, 0);
        sys$getdviw(0, repchan, 0, it, (void *) jiosb, 0, 0, 0);
        snprintf(prc, sizeof prc, "STW%u_%u", u1, u2);
        snprintf(reqname, sizeof reqname, "_MBA%u:", u1);
        snprintf(repname, sizeof repname, "_MBA%u:", u2);
    }
    (void) len;
    sys$qiow(0, reqchan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0, (void *) table, strlen(table), 0, 0, 0, 0);
    sys$qiow(0, reqchan, IO$_WRITEVBLK | IO$M_NOW, (void *) iosb, 0, 0, (void *) pattern, strlen(pattern), 0, 0, 0, 0);
    desc_set(&img, "SYS$SYSTEM:LOGINOUT.EXE", 23);
    desc_set(&in, proc, (unsigned short) strlen(proc));
    desc_set(&nl, log, (unsigned short) strlen(log));
    desc_set(&pn, prc, (unsigned short) strlen(prc));
    st = sys$creprc(&pid, &img, &in, &nl, &nl, 0, 0, &pn, 4, 0, 0, 0x200 /* PRC$M_DETACH */, 0, 0);
    printf("  [persona] $CREPRC detached %s on %s: %s, pid %08X\n", prc, proc, msg(st), pid);
    while ((st & 1) && !done && idle < 1000) {
        unsigned int q = sys$qiow(0, repchan, IO$_READVBLK | IO$M_NOW, (void *) iosb, 0, 0, buf, 1024 /* not past maxmsg: MBTOOSML */, 0, 0, 0, 0);
        if ((q & 1) && (iosb[0] & 1)) {
            buf[iosb[1]] = '\0';
            if (!strcmp(buf, "%%END%%")) { done = 1; break; }
            lines++;
            if (buf[0] == ' ' && buf[1] == ' ' && buf[2] == '"') names++;
            if (lines <= 5 || buf[0] == '%') printf("    | %s\n", buf);
            idle = 0;
            continue;
        }
        if (idle == 0 || idle == 999) printf("  [persona] read: $QIOW %s, iosb %%X%04X\n", msg(q), iosb[0]);
        lib$wait(&tick, 0, &ieee_s);
        idle++;
    }
    sys$gettim((void *) t1);
    printf("  [persona] %s %s: %d lines, %d names, %s, %.0f ms\n", table, pattern, lines, names,
           done ? "complete" : "TIMED OUT",
           ((double) t1[0] - (double) t0[0] + 4294967296.0 * ((double) t1[1] - (double) t0[1])) / 10000.0);
    if (!done && pid) {
        unsigned int state = 0;
        ile3 j[2];
        ile3_set(&j[0], JPI$_STATE, &state, 4, 0); ile3_end(&j[1]);
        sys$getjpiw(0, &pid, 0, j, (void *) jiosb, 0, 0, 0);
        printf("  [persona] detached process state %u; last read iosb %%X%04X, %u bytes\n", state, iosb[0], iosb[1]);
        printf("  [persona] stop it: %s\n", msg(sys$delprc(&pid, 0, 0)));
    }
    sys$dassgn(reqchan);
    sys$dassgn(repchan);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    unsigned int imp[2] = { PRV$M_DETACH | PRV$M_SYSPRV, 0 };
    unsigned int sysprv[2] = { PRV$M_SYSPRV, 0 };
    const char *table = argc > 2 ? argv[2] : "LNM$SYSTEM_TABLE";
    struct dsc$descriptor_s d;
    char user[13];
    size_t i;

    if (argc < 2) { printf("usage: probe_lnm <username> [table]\n"); return 1; }
    for (i = 0; argv[1][i] && i < 12; i++) user[i] = (char) ((argv[1][i] >= 'a' && argv[1][i] <= 'z') ? argv[1][i] - 32 : argv[1][i]);
    user[i] = '\0';
    printf("probe_lnm: %s, table %s\n", user, table);

    spawn("natural", table);

    report("$SETPRV IMPERSONATE,SYSPRV", sys$setprv(1, (void *) imp, 0, 0));
    desc_set(&d, user, (unsigned short) strlen(user));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    sys$setprv(0, (void *) sysprv, 0, 0);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        struct dsc$descriptor_s c, nl;
        unsigned int s2, status = 0;
        static const char cmd[] = "SHOW LOGICAL/TABLE=LNM$SYSTEM_TABLE SYS$SYSDEVICE";
        spawn("persona", table);
        desc_set(&c, cmd, sizeof cmd - 1);
        desc_set(&nl, "NLA0:", 5);
        s2 = lib$spawn(&c, 0, &nl, 0, 0, 0, &status);
        printf("  [persona] LIB$SPAWN output NLA0: %s, completion %%X%08X\n", msg(s2), status);
        s2 = lib$spawn(&c, 0, 0, 0, 0, 0, &status);
        printf("  [persona] LIB$SPAWN inheriting output: %s, completion %%X%08X\n", msg(s2), status);
        {
            unsigned int flags = 0x2 | 0x4 | 0x8 | 0x20;   /* NOCLISYM NOLOGNAM NOKEYPAD NOCONTROL */
            static const char who[] = "WRITE SYS$OUTPUT \"user=\", F$EDIT(F$GETJPI(\"\",\"USERNAME\"),\"TRIM\")";
            struct dsc$descriptor_s w;
            desc_set(&w, who, sizeof who - 1);
            s2 = lib$spawn(&c, 0, &nl, &flags, 0, 0, &status);
            printf("  [persona] LIB$SPAWN, no symbols/logicals copied, output NLA0: %s, completion %%X%08X\n", msg(s2), status);
            s2 = lib$spawn(&w, 0, 0, &flags, 0, 0, &status);
            printf("  [persona] LIB$SPAWN, no symbols/logicals copied, output inherited: %s, completion %%X%08X\n", msg(s2), status);
        }
        /* A subprocess hangs, natural or not: LOGINOUT waits for the parent's CLI to
           send it context, as LIB$SPAWN does (state LEF, no image). Detached does not. */
        /* Mailbox input: LOGINOUT takes it for a terminal and waits at a sign-in prompt.
           A subprocess waits for its parent CLI's context. D14: a procedure file. */
        const char *log = getenv("PROBE_LNM_LOG") ? getenv("PROBE_LNM_LOG") : "NLA0:";
        lnm_run("STEWARD$ROOT:[COM]STEWARD_LNM_PROBE.COM", "LNM$SYSTEM_TABLE", "SYS$S*", log);
        lnm_run("STEWARD$ROOT:[COM]STEWARD_LNM_PROBE.COM", "LNM$SYSTEM_TABLE", "*", log);
        lnm_run("STEWARD$ROOT:[COM]STEWARD_LNM_PROBE.COM", "LNM$GROUP", "*", log);
        lnm_run("STEWARD$ROOT:[COM]STEWARD_LNM_PROBE.COM", "LNM$SYSTEM_DIRECTORY", "*", log);
        lnm_run("STEWARD$ROOT:[COM]STEWARD_LNM_PROBE.COM", "LNM$SYSTEM_TABLE/OUTPUT=X", "*", log);
    }

    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    spawn("reverted", table);
    return 1;
}
