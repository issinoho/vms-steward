/* probe_sshdates.c - how fast can the SSH logs' dates be read? (read-only)

   Usage: probe_sshdates [max-rms-opens]

   Walks SSH$ROOT:[VAR]*_*.LOG;* three times and times each:
     1. $SEARCH alone;
     2. $SEARCH, then the creation and revision dates from the file header with an
        ACP IO$_ACCESS on the file ID (no RMS open, no record stream);
     3. $SEARCH, then RMS $OPEN with a XABDAT and $CLOSE, as ax_ssh_logs does, for
        at most max-rms-opens files (default 1000), so it does not take half an hour.
   The IA64 node has 27,409 such logs and one access-history request took 1,579 s
   (NOTES.md). The FIB is filled by offset (FIBDEF on the node: acctl at 0, fid at 4,
   length 96): its members are inside variant unions. Changes nothing. */
#include <stdlib.h>
#include <rms.h>
#include <iodef.h>
#include <atrdef.h>
#include <ssdef.h>
#include <rmsdef.h>
#include "probe_common.h"

static double now_s(void)
{
    unsigned int q[2];
    sys$gettim((void *) q);
    return ((double) q[1] * 4294967296.0 + (double) q[0]) / 1e7;
}

static int walk(int mode, int maxopen, unsigned int *firstbad)
{
    static const char spec[] = "SSH$ROOT:[VAR]*_*.LOG;*";
    char esa[256], rsa[256];
    struct FAB fab = cc$rms_fab;
    struct NAM nam = cc$rms_nam;
    unsigned short chan = 0;
    unsigned int st;
    int n = 0;
    fab.fab$l_fna = (char *) spec;
    fab.fab$b_fns = (unsigned char) (sizeof spec - 1);
    fab.fab$l_nam = &nam;
    nam.nam$l_esa = esa; nam.nam$b_ess = sizeof esa - 1;
    nam.nam$l_rsa = rsa; nam.nam$b_rss = sizeof rsa - 1;
    if (!((st = sys$parse(&fab)) & 1)) { printf("  $PARSE %s\n", msg(st)); return -1; }
    while ((st = sys$search(&fab)) & 1) {
        if (mode == 2) {
            unsigned char fib[96];
            unsigned int cre[2], rev[2];
            unsigned short iosb[4];
            struct dsc$descriptor_s fd;
            struct { unsigned short size, type; void *addr; } atr[3];
            if (!chan) {
                struct dsc$descriptor_s dd;
                desc_set(&dd, (char *) nam.nam$t_dvi + 1, nam.nam$t_dvi[0]);
                if (!((st = sys$assign(&dd, &chan, 0, 0)) & 1)) { printf("  $ASSIGN %s\n", msg(st)); return -1; }
            }
            memset(fib, 0, sizeof fib);
            memcpy(fib + 4, nam.nam$w_fid, 6);
            fd.dsc$w_length = sizeof fib; fd.dsc$b_dtype = DSC$K_DTYPE_Z;
            fd.dsc$b_class = DSC$K_CLASS_S; fd.dsc$a_pointer = (char *) fib;
            atr[0].size = ATR$S_CREDATE; atr[0].type = ATR$C_CREDATE; atr[0].addr = cre;
            atr[1].size = ATR$S_REVDATE; atr[1].type = ATR$C_REVDATE; atr[1].addr = rev;
            atr[2].size = 0; atr[2].type = 0; atr[2].addr = 0;
            st = sys$qiow(0, chan, IO$_ACCESS, (void *) iosb, 0, 0, &fd, 0, 0, 0, atr, 0);
            if (st & 1) st = iosb[0];
            if (!(st & 1) && !*firstbad) *firstbad = st;
        } else if (mode == 3) {
            struct FAB f = cc$rms_fab;
            struct XABDAT dat = cc$rms_xabdat;
            if (n >= maxopen) break;
            rsa[nam.nam$b_rsl] = '\0';
            f.fab$l_fna = rsa; f.fab$b_fns = nam.nam$b_rsl;
            f.fab$b_fac = FAB$M_GET; f.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_UPI;
            f.fab$l_xab = &dat;
            st = sys$open(&f);
            if (st & 1) sys$close(&f); else if (!*firstbad) *firstbad = st;
        }
        n++;
    }
    if (chan) sys$dassgn(chan);
    return n;
}

int main(int argc, char **argv)
{
    int maxopen = argc > 1 ? atoi(argv[1]) : 1000, mode, n;
    static const char *what[] = { "", "$SEARCH only", "$SEARCH + ACP dates", "$SEARCH + RMS open" };
    for (mode = 1; mode <= 3; mode++) {
        unsigned int bad = 0;
        double t0 = now_s(), dt;
        n = walk(mode, maxopen, &bad);
        dt = now_s() - t0;
        printf("%-22s %6d files  %8.2f s  %6.2f ms/file%s%s\n", what[mode], n, dt,
               n > 0 ? dt * 1000.0 / n : 0.0, bad ? "  first error " : "", bad ? msg(bad) : "");
    }
    return 1;
}
