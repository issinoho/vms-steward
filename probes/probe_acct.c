/* probe_acct.c - can Steward read the accounting file itself? (Phase 6, read-only)

   Usage: probe_acct [file] [max]       (default SYS$MANAGER:ACCOUNTNG.DAT, last 12)

   Reads the file with RMS, shared (the accounting manager keeps writing it), and walks
   each record's packets using ACRDEF's own definitions (SYS$STARLET_C): the record
   header (type, length, event time), then packets, each with its own type and length.
   For process deletions (ACR$K_PRCDEL, by subtype: interactive, network, batch, ...)
   and login failures (ACR$K_LOGFAIL) it prints user, PID, start and finish, terminal,
   remote ID and remote full name, and final status, to compare with ACCOUNTING/FULL.
   Changes nothing. */
#include <stdlib.h>
#include <rms.h>
#include <ssdef.h>
#include <acrdef.h>
#include "probe_common.h"

static const char *kind(unsigned sub)
{
    static const char *k[] = { "?", "INTERACTIVE", "SUBPROCESS", "DETACHED", "BATCH", "NETWORK" };
    return sub < 6 ? k[sub] : "?";
}

/* A counted string at off (from the packet start); "" if absent or out of range. */
static void ascic(const unsigned char *pkt, unsigned plen, unsigned off, char *out, size_t outlen)
{
    unsigned n;
    out[0] = '\0';
    if (!off || off >= plen) return;
    n = pkt[off];
    if (off + 1 + n > plen) return;
    if (n >= outlen) n = (unsigned) outlen - 1;
    memcpy(out, pkt + off + 1, n);
    out[n] = '\0';
}

/* A word-counted string: the remote full name is one (2-byte count; found by dumping a
   record, 2026-10-11: "0D 00 31 39 32 ..." = 13 bytes, "192.168.0.131"). */
static void asciw(const unsigned char *pkt, unsigned plen, unsigned off, char *out, size_t outlen)
{
    unsigned n;
    out[0] = '\0';
    if (!off || off + 2 > plen) return;
    n = pkt[off] | pkt[off + 1] << 8;
    if (off + 2 + n > plen) return;
    if (n >= outlen) n = (unsigned) outlen - 1;
    memcpy(out, pkt + off + 2, n);
    out[n] = '\0';
}

static void vmstime(unsigned long long t, char *out)
{
    unsigned short len = 0;
    unsigned int q[2];
    struct dsc$descriptor_s d;
    q[0] = (unsigned int) t; q[1] = (unsigned int) (t >> 32);
    desc_set(&d, out, 23);
    if (!t || !(sys$asctim(&len, &d, (void *) q, 0) & 1)) len = 0;
    out[len] = '\0';
}

int main(int argc, char **argv)
{
    struct FAB fab = cc$rms_fab;
    struct RAB rab = cc$rms_rab;
    static unsigned char rec[32768];
    const char *file = argc > 1 ? argv[1] : "SYS$MANAGER:ACCOUNTNG.DAT";
    int max = argc > 2 ? atoi(argv[2]) : 12;
    static char lines[4096][200];
    unsigned int st, n = 0, total = 0, shown;

    fab.fab$l_fna = (char *) file; fab.fab$b_fns = (unsigned char) strlen(file);
    fab.fab$b_fac = FAB$M_GET;
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD;
    st = sys$open(&fab);
    report("$OPEN accounting file", st);
    if (!(st & 1)) return 1;
    rab.rab$l_fab = &fab;
    rab.rab$l_ubf = (char *) rec; rab.rab$w_usz = sizeof rec;
    rab.rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    st = sys$connect(&rab);
    if (!(st & 1)) { report("$CONNECT", st); return 1; }

    while ((st = sys$get(&rab)) & 1) {
        unsigned rlen = rab.rab$w_rsz, w = rec[0] | rec[1] << 8, type = (w >> 1) & 0x7F, sub = (w >> 8) & 0xF;
        unsigned long long systime = 0, login = 0;
        unsigned off = ACR$K_HDRLEN, status = 0, pid = 0;
        char user[40] = "", term[40] = "", rid[64] = "", full[128] = "", node[40] = "", queue[40] = "";
        char t1[24], t2[24];
        int i;
        total++;
        if (rlen < ACR$K_HDRLEN || (w & 1)) continue;          /* records, not stray packets */
        if (type != ACR$K_PRCDEL && type != ACR$K_LOGFAIL) continue;
        for (i = 0; i < 8; i++) systime |= (unsigned long long) rec[4 + i] << (8 * i);
        while (off + 4 <= rlen) {                            /* the packets */
            const unsigned char *p = rec + off;
            unsigned pw = p[0] | p[1] << 8, plen = p[2] | p[3] << 8, ptype = (pw >> 1) & 0x7F;
            if (plen < 4 || off + plen > rlen) break;
            if (ptype == ACR$K_ID) {
                const ACRDEF2 *id = (const ACRDEF2 *) p;
                pid = id->acr$l_pid;
                ascic(p, plen, id->acr$w_username, user, sizeof user);
                ascic(p, plen, id->acr$w_terminal, term, sizeof term);
                ascic(p, plen, id->acr$w_nodename, node, sizeof node);
                ascic(p, plen, id->acr$w_remoteid, rid, sizeof rid);
                ascic(p, plen, id->acr$w_queue, queue, sizeof queue);
                if (id->acr$v_fullname) asciw(p, plen, id->acr$w_fullname, full, sizeof full);
            } else if (ptype == ACR$K_RESOURCE) {
                const ACRDEF3 *r = (const ACRDEF3 *) p;
                login = r->acr$q_login;
                status = r->acr$l_status;
            }
            off += plen;
        }
        vmstime(login, t1);
        vmstime(systime, t2);
        snprintf(lines[n % 4096], sizeof lines[0], "%-11s %-12s pid %08X  %s -> %s  term \"%s\" node \"%s\" rid \"%s\" full \"%s\" queue \"%s\" status %%X%08X",
                 type == ACR$K_LOGFAIL ? "LOGFAIL" : kind(sub), user, pid, t1, t2, term, node, rid, full, queue, status);
        n++;
    }
    report("end of file", st);
    printf("  %u records, %u process/logfail records; the last %d:\n", total, n, max);
    for (shown = n > (unsigned) max ? n - max : 0; shown < n; shown++) printf("  %s\n", lines[shown % 4096]);
    sys$close(&fab);
    return 1;
}
