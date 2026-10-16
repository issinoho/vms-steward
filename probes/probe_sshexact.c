/* probe_sshexact.c - in a large directory, is opening a log by its exact name fast?

   Usage: probe_sshexact <dir> [files] [lookups]       e.g. [.SSHX] 5000 400

   CHANGES ONLY <dir>, which must be a scratch directory of the work account's own: it
   creates <files> empty files named like OpenSSH's per-connection logs
   (<node>_<host>_<pid>.log), then times
     1. a wildcard $SEARCH of <dir>*_*.LOG;* (what ax_ssh_logs does now);
     2. <lookups> RMS opens by exact name, spread over the directory;
     3. the same number of exact opens of names that do not exist (purged logs);
   and deletes every file it created. On IA64 the wildcard walk of 27,651 real logs
   took 1,995 s (NOTES.md); this shows whether exact names avoid that cost. */
#include <stdlib.h>
#include <rms.h>
#include <rmsdef.h>
#include <ssdef.h>
#include "probe_common.h"

static double now_s(void)
{
    unsigned int q[2];
    sys$gettim((void *) q);
    return ((double) q[1] * 4294967296.0 + (double) q[0]) / 1e7;
}

static void name_of(char *out, size_t n, const char *dir, unsigned int i)
{
    /* hosts as a DHCP network gives them; pids as VMS hands them out */
    snprintf(out, n, "%sprobe_host-%u_%08X.log", dir, i % 7, 0x0001C000u + i);
}

static unsigned int open_close(const char *spec)
{
    struct FAB f = cc$rms_fab;
    unsigned int st;
    f.fab$l_fna = (char *) spec; f.fab$b_fns = (unsigned char) strlen(spec);
    f.fab$b_fac = FAB$M_GET; f.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_UPI;
    st = sys$open(&f);
    if (st & 1) sys$close(&f);
    return st;
}

int main(int argc, char **argv)
{
    const char *dir;
    int files, lookups, i, made = 0, n = 0, ok = 0, fnf = 0;
    char spec[256];
    double t0;
    if (argc < 2) { printf("usage: probe_sshexact <dir> [files] [lookups]\n"); return 1; }
    dir = argv[1];
    files = argc > 2 ? atoi(argv[2]) : 5000;
    lookups = argc > 3 ? atoi(argv[3]) : 400;

    t0 = now_s();
    for (i = 0; i < files; i++) {
        struct FAB f = cc$rms_fab;
        name_of(spec, sizeof spec, dir, (unsigned int) i);
        f.fab$l_fna = spec; f.fab$b_fns = (unsigned char) strlen(spec);
        f.fab$b_rfm = FAB$C_VAR; f.fab$b_rat = FAB$M_CR;
        if (sys$create(&f) & 1) { sys$close(&f); made++; }
    }
    printf("created %d of %d files in %.2f s\n", made, files, now_s() - t0);

    {   /* 1. the wildcard walk */
        char esa[256], rsa[256], wild[256];
        struct FAB fab = cc$rms_fab;
        struct NAM nam = cc$rms_nam;
        snprintf(wild, sizeof wild, "%s*_*.LOG;*", dir);
        fab.fab$l_fna = wild; fab.fab$b_fns = (unsigned char) strlen(wild);
        fab.fab$l_nam = &nam;
        nam.nam$l_esa = esa; nam.nam$b_ess = sizeof esa - 1;
        nam.nam$l_rsa = rsa; nam.nam$b_rss = sizeof rsa - 1;
        t0 = now_s();
        if (sys$parse(&fab) & 1) while (sys$search(&fab) & 1) n++;
        printf("wildcard $SEARCH     %6d files  %8.3f s\n", n, now_s() - t0);
    }
    t0 = now_s();   /* 2. exact names that exist */
    for (i = 0; i < lookups; i++) {
        name_of(spec, sizeof spec, dir, (unsigned int) ((long) i * made / (lookups ? lookups : 1)));
        if (open_close(spec) & 1) ok++;
    }
    printf("exact opens, present %6d of %d  %8.3f s\n", ok, lookups, now_s() - t0);
    t0 = now_s();   /* 3. exact names that do not */
    for (i = 0; i < lookups; i++) {
        snprintf(spec, sizeof spec, "%sprobe_gone_%08X.log", dir, 0x00020000u + (unsigned int) i);
        if (open_close(spec) == RMS$_FNF) fnf++;
    }
    printf("exact opens, missing %6d FNF of %d  %8.3f s\n", fnf, lookups, now_s() - t0);

    t0 = now_s();
    for (i = 0; i < files; i++) {
        struct FAB f = cc$rms_fab;
        name_of(spec, sizeof spec, dir, (unsigned int) i);
        f.fab$l_fna = spec; f.fab$b_fns = (unsigned char) strlen(spec);
        sys$erase(&f);
    }
    printf("deleted in %.2f s\n", now_s() - t0);
    return 1;
}
