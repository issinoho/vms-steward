/* probe_uaf.c - can we enumerate SYSUAF, and does $GETUAI agree with what we read? (read-only)

   Usage: probe_uaf [max]

   No system service lists the users in SYSUAF, so a "list users" call must read the
   file itself. This opens SYSUAF for shared read with no record locking (RRL+NLK, so
   it never blocks AUTHORIZE or LOGINOUT), takes the username from each record at
   offset 4 (UAF$T_USERNAME, 32 bytes, blank-padded), and calls $GETUAI on it for the
   UIC, flags and owner, so the offset is checked against the system's own reading.

   Answers: whether the RMS approach works, how long a full pass takes, and which
   privilege it needs (run once as a SYSPRV holder and once without). Changes nothing. */
#include <stdlib.h>
#include <time.h>
#include <rms.h>
#include <ssdef.h>
#include <uaidef.h>
#include "probe_common.h"

int main(int argc, char **argv)
{
    struct FAB fab = cc$rms_fab;
    struct RAB rab = cc$rms_rab;
    static char rec[2048];
    unsigned int st, n = 0, bad = 0, max = argc > 1 ? (unsigned int) atoi(argv[1]) : 10;
    clock_t t0 = clock();

    fab.fab$l_fna = "SYSUAF";            fab.fab$b_fns = 6;
    fab.fab$l_dna = "SYS$SYSTEM:.DAT";   fab.fab$b_dns = 15;
    fab.fab$b_fac = FAB$M_GET;
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_SHRDEL;

    printf("probe_uaf: sequential read of SYSUAF\n");
    st = sys$open(&fab);
    report("$OPEN SYSUAF", st);
    if (!(st & 1)) return 1;
    rab.rab$l_fab = &fab;
    rab.rab$b_rac = RAB$C_SEQ;
    rab.rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    rab.rab$l_ubf = rec; rab.rab$w_usz = sizeof rec;
    st = sys$connect(&rab);
    report("$CONNECT", st);
    if (!(st & 1)) { sys$close(&fab); return 1; }

    while ((st = sys$get(&rab)) & 1) {
        char user[33]; unsigned int uic = 0, flags = 0, gst; char owner[33];
        unsigned short olen = 0; struct dsc$descriptor_s d; ile3 items[4];
        if (rab.rab$w_rsz < 36) { bad++; continue; }
        memcpy(user, rec + 4, 32); user[32] = '\0'; rtrim(user);
        n++;
        desc_set(&d, user, (unsigned short) strlen(user));
        ile3_set(&items[0], UAI$_UIC, &uic, 4, 0);
        ile3_set(&items[1], UAI$_FLAGS, &flags, 4, 0);
        ile3_set(&items[2], UAI$_OWNER, owner, 32, &olen);
        ile3_end(&items[3]);
        gst = sys$getuai(0, 0, &d, items, 0, 0, 0);
        if (!(gst & 1)) bad++;
        if (n <= max) {
            /* UAI$_OWNER is a counted string: length byte first. */
            int ol = (gst & 1) && olen ? (unsigned char) owner[0] : 0;
            printf("    %-12s [%o,%o] flags %%X%08X owner \"%.*s\" %s\n", user,
                   uic >> 16, uic & 0xFFFF, flags, ol, owner + 1, (gst & 1) ? "" : msg(gst));
        }
    }
    report("end of file", st);
    printf("  records: %u, $GETUAI failures or short records: %u, %.2f s CPU\n",
           n, bad, (double) (clock() - t0) / CLOCKS_PER_SEC);
    sys$disconnect(&rab);
    sys$close(&fab);
    return 1;
}
