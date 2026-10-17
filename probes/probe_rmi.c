/* probe_rmi.c - what can $GETRMI tell an unprivileged process, and how fast? (Phase 13)

   Usage: probe_rmi [seconds]          (default 5)

   Run with every privilege off but TMPMBX and NETMBX (SET PROCESS/PRIVILEGE=(NOALL,
   TMPMBX,NETMBX)): reads the CPU mode counters, the system-wide I/O, paging and
   process-state items twice, the given seconds apart, and prints each value, its
   change and the change a second. Then dumps the first bytes of RMI$_MODES (every
   mode on every CPU) and RMI$_DISKS (every disk), whose layouts the header gives only
   in part, and times three readings of everything.

   Questions (PHASE13.md): does $GETRMI need privilege; are the mode counters ticks
   summed over CPUs (their changes should add up to 100 a second a CPU); which items
   need 4-byte buffers (BADPARAM with 8, as RMI$_CUR does, NOTES.md); and is one reading
   cheap enough to take every few seconds? Found: $GETRMI writes the return length as
   a longword, 2 bytes past an unsigned short (layout(), the first pass, shows it). Item codes from RMIDEF on the node.
   Changes nothing. */
#include <stdlib.h>
#include <time.h>
#include <ssdef.h>
#include <rmidef.h>
#include <lib$routines.h>
#include "probe_common.h"

typedef struct { const char *name; unsigned short code, size; } rmi_item;

static const rmi_item items[] = {
    { "CPUINTSTK", RMI$_CPUINTSTK, 8 }, { "CPUMPSYNCH", RMI$_CPUMPSYNCH, 8 },
    { "CPUKERNEL", RMI$_CPUKERNEL, 8 }, { "CPUEXEC", RMI$_CPUEXEC, 8 },
    { "CPUSUPER", RMI$_CPUSUPER, 8 }, { "CPUUSER", RMI$_CPUUSER, 8 },
    { "CPUIDLE", RMI$_CPUIDLE, 8 },
    { "DIRIO", RMI$_DIRIO, 4 }, { "BUFIO", RMI$_BUFIO, 4 },
    { "FAULTS", RMI$_FAULTS, 4 }, { "PREADIO", RMI$_PREADIO, 4 },
    { "PWRITIO", RMI$_PWRITIO, 4 }, { "ISWPCNT", RMI$_ISWPCNT, 4 },
    { "MBREADS", RMI$_MBREADS, 4 }, { "MBWRITES", RMI$_MBWRITES, 4 },
    { "TTREADS", RMI$_TTREADS, 4 }, { "TTWRITES", RMI$_TTWRITES, 4 },
    { "FRLIST", RMI$_FRLIST, 8 }, { "MODLIST", RMI$_MODLIST, 8 },
    { "PROCS", RMI$_PROCS, 4 }, { "CUR", RMI$_CUR, 4 }, { "COM", RMI$_COM, 4 },
    { "COMO", RMI$_COMO, 4 }, { "LEF", RMI$_LEF, 4 }, { "HIB", RMI$_HIB, 4 },
    { "PFW", RMI$_PFW, 4 }, { "MWAIT", RMI$_MWAIT, 4 },
    { "LEFO", RMI$_LEFO, 4 }, { "HIBO", RMI$_HIBO, 4 }, { "SUSP", RMI$_SUSP, 4 },
    { "SUSPO", RMI$_SUSPO, 4 }, { "CEF", RMI$_CEF, 4 }, { "COLPG", RMI$_COLPG, 4 },
    { "FPG", RMI$_FPG, 4 },
    { "PROCS8", RMI$_PROCS, 8 }, { "DIRIO8", RMI$_DIRIO, 8 },   /* BADPARAM: they want 4 */
};
#define NITEMS (sizeof items / sizeof items[0])

static unsigned int efn;   /* our own: with EF 0, $SYNCH spun when the IOSB stayed empty */
static int trace;          /* print each item before asking for it (first reading) */

/* One item alone, so a refusal (or a hang) is the item's own. */
static unsigned int one(unsigned short code, void *buf, unsigned short size, unsigned short *len)
{
    unsigned int iosb[2] = { 0, 0 }, st;
    ile3 it[2];
    ile3_set(&it[0], code, buf, size, len);
    ile3_end(&it[1]);
    if (trace) { printf("  asking for item %u, %u bytes\n", code, size); fflush(stdout); }
    st = sys$getrmi(efn, 0, 0, it, iosb, 0, 0);
    if (trace) { printf("  $GETRMI %s, IOSB %08X\n", msg(st), iosb[0]); fflush(stdout); }
    if (st & 1) st = sys$synch(efn, iosb);
    if (st & 1) st = iosb[0] & 0xFFFF;
    return st;
}

/* What does each item write? Its buffer and return length sit among guard bytes
   (0xA5), and anything $GETRMI writes past either is reported. */
static void layout(void)
{
    size_t i;
    for (i = 0; i < NITEMS; i++) {
        static struct { unsigned char before[8], buf[8], after[64]; } b;
        static struct { unsigned char before[8]; unsigned short len; unsigned char after[14]; } l;
        unsigned int st, j, over = 0, lover = 0;
        memset(&b, 0xA5, sizeof b);
        memset(&l, 0xA5, sizeof l);
        st = one(items[i].code, b.buf, items[i].size, &l.len);
        for (j = 0; j < sizeof b.after; j++) if (b.after[j] != 0xA5) over = j + 1;
        for (j = 0; j < sizeof l.after; j++) if (l.after[j] != 0xA5) lover = j + 1;
        printf("%-11s asked %u: %s, length %u, %u bytes past the buffer, %u past the length%s\n",
               items[i].name, items[i].size, msg(st), l.len, over, lover,
               (b.before[7] != 0xA5 || l.before[7] != 0xA5) ? ", AND BEFORE" : "");
        if (over) {
            printf("  ");
            for (j = 0; j < 8 + over && j < 72; j++) printf("%02X", j < 8 ? b.buf[j] : b.after[j - 8]);
            printf("\n");
        }
        fflush(stdout);
    }
}

/* Every item in one call, each with a longword return length, as st_plat_monitor
   asks (the pair with 8 bytes that want 4 left out). */
static void batch(void)
{
    static unsigned long long v[NITEMS];
    static unsigned int len[NITEMS];
    static ile3 it[NITEMS + 1];
    unsigned int iosb[2] = { 0, 0 }, st;
    size_t i, n = 0;
    for (i = 0; i < NITEMS; i++) {
        if (!strcmp(items[i].name, "PROCS8") || !strcmp(items[i].name, "DIRIO8")) continue;
        ile3_set(&it[n++], items[i].code, &v[i], items[i].size, (unsigned short *) &len[i]);
    }
    ile3_end(&it[n]);
    st = sys$getrmi(efn, 0, 0, it, iosb, 0, 0);
    if (st & 1) st = sys$synch(efn, iosb);
    if (st & 1) st = iosb[0] & 0xFFFF;
    printf("%u items in one $GETRMI: %s; CPUIDLE %llu, PROCS %llu\n", (unsigned) n, msg(st), v[6], v[19]);
}

static void read_all(unsigned long long v[], unsigned int st[])
{
    size_t i;
    for (i = 0; i < NITEMS; i++) {
        unsigned int len[2] = { 0, 0 };   /* $GETRMI writes 4 bytes here, not 2 */
        v[i] = 0;
        st[i] = one(items[i].code, &v[i], items[i].size, (unsigned short *) len);
    }
}

static void dump(const char *what, unsigned short code)
{
    static unsigned char buf[8192];
    unsigned int len = 0, st, i;   /* $GETRMI writes 4 bytes here, not 2 */
    memset(buf, 0, sizeof buf);
    st = one(code, buf, sizeof buf, (unsigned short *) &len);
    printf("%s: %s, %u bytes returned\n", what, msg(st), len);
    for (i = 0; i < len && i < 160; i += 16) {
        unsigned int j;
        printf("  %04X ", i);
        for (j = 0; j < 16 && i + j < len; j++) printf(" %02X", buf[i + j]);
        printf("   ");
        for (j = 0; j < 16 && i + j < len; j++) putchar(buf[i + j] >= 32 && buf[i + j] < 127 ? buf[i + j] : '.');
        putchar('\n');
    }
}

int main(int argc, char **argv)
{
    static unsigned long long a[NITEMS], b[NITEMS];
    static unsigned int sa[NITEMS], sb[NITEMS];
    float secs = argc > 1 ? (float) atof(argv[1]) : 5.0f;
    int float_type = 4;   /* LIB$K_IEEE_S: LIB$WAIT reads VAX F_floating otherwise (NOTES.md) */
    unsigned long long modes = 0;
    clock_t c0, c1;
    time_t t0;
    size_t i;
    int k;

    if (secs <= 0) secs = 5.0f;
    if (!(lib$get_ef(&efn) & 1)) { printf("no event flag\n"); return 1; }
    layout();
    batch();
    if (argc > 2) return 0;   /* "probe_rmi 5 layout": that only */
    read_all(a, sa);
    lib$wait(&secs, 0, &float_type);
    read_all(b, sb);
    printf("%-11s %-6s %20s %14s %12s\n", "item", "size", "second reading", "change", "a second");
    for (i = 0; i < NITEMS; i++) {
        if (!(sa[i] & 1) || !(sb[i] & 1)) { printf("%-11s %-6u %s\n", items[i].name, items[i].size, msg(sb[i] & 1 ? sa[i] : sb[i])); continue; }
        printf("%-11s %-6u %20llu %14lld %12.1f\n", items[i].name, items[i].size, b[i],
               (long long) (b[i] - a[i]), (double) (long long) (b[i] - a[i]) / secs);
        if (i < 7) modes += b[i] - a[i];
    }
    printf("mode changes summed: %llu ticks in %.1f s (%.1f a second; 100 a second a CPU)\n",
           modes, secs, (double) modes / secs);

    dump("RMI$_MODES", RMI$_MODES);
    dump("RMI$_DISKS", RMI$_DISKS);

    c0 = clock();
    t0 = time(NULL);
    for (k = 0; k < 3; k++) read_all(a, sa);
    c1 = clock();
    printf("3 readings of %u items, one $GETRMI each: %.1f ms CPU and %.1f s elapsed each\n", (unsigned) NITEMS,
           (double) (c1 - c0) * 1000.0 / CLOCKS_PER_SEC / 3, (double) (time(NULL) - t0) / 3);
    return 0;
}
