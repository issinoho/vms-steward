/* probe_audit.c - can Steward read login failures and break-ins from the security
   audit journal itself? (Phase 6, read-only)

   Usage: probe_audit [journal]     (default SYS$MANAGER:SECURITY.AUDIT$JOURNAL)

   Opens the journal shared (the audit server keeps it open for writing) and walks
   each record with NSAMSGDEF's definitions (SYS$STARLET_C): a 20-byte header (event
   type, subtype, packet count, record size, version), then packets of {size, type,
   data}. For LOGFAIL (NSA$C_MSG_LOGFAIL) and BREAKIN (NSA$C_MSG_BREAKIN) it prints
   the time stamp, username, terminal, remote node, user and full name, PID and final
   status, to compare with ANALYZE/AUDIT. The first such record is also dumped raw,
   to settle whether a packet's size includes its header. Changes nothing. */
#include <stdlib.h>
#include <rms.h>
#include <ssdef.h>
#include <nsadef.h>
#include "probe_common.h"

static const char *subtype(unsigned s)
{
    static const char *n[] = { "?", "BATCH", "DETACHED", "DIALUP", "LOCAL", "NETWORK", "REMOTE", "SUBPROCESS" };
    return s < 8 ? n[s] : "?";
}

static void vmstime(const unsigned char *p, char *out)
{
    unsigned short len = 0;
    unsigned int q[2];
    struct dsc$descriptor_s d;
    memcpy(q, p, 8);
    desc_set(&d, out, 23);
    if (!(sys$asctim(&len, &d, (void *) q, 0) & 1)) len = 0;
    out[len] = '\0';
}

static void text(const unsigned char *p, unsigned n, char *out, size_t outlen)
{
    unsigned i;
    if (n >= outlen) n = (unsigned) outlen - 1;
    for (i = 0; i < n; i++) out[i] = (p[i] >= 32 && p[i] < 127) ? (char) p[i] : '.';
    out[n] = '\0';
}

int main(int argc, char **argv)
{
    struct FAB fab = cc$rms_fab;
    struct RAB rab = cc$rms_rab;
    static unsigned char rec[8192];
    const char *file = argc > 1 ? argv[1] : "SYS$MANAGER:SECURITY.AUDIT$JOURNAL";
    unsigned int st, total = 0, shown = 0;
    int dumped = 0;

    fab.fab$l_fna = (char *) file; fab.fab$b_fns = (unsigned char) strlen(file);
    fab.fab$b_fac = FAB$M_GET;
    fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD | FAB$M_UPI;
    st = sys$open(&fab);
    report("$OPEN journal", st);
    if (!(st & 1)) return 1;
    rab.rab$l_fab = &fab;
    rab.rab$l_ubf = (char *) rec; rab.rab$w_usz = sizeof rec;
    rab.rab$l_rop = RAB$M_RRL | RAB$M_NLK;
    st = sys$connect(&rab);
    if (!(st & 1)) { report("$CONNECT", st); return 1; }
    printf("  NSA$C_MSG_HDR_LENGTH %d, NSA$C_PKT_HDR_LENGTH %d\n", NSA$C_MSG_HDR_LENGTH, NSA$C_PKT_HDR_LENGTH);

    while ((st = sys$get(&rab)) & 1) {
        unsigned rlen = rab.rab$w_rsz, type = rec[0] | rec[1] << 8, sub = rec[2] | rec[3] << 8;
        unsigned npk = rec[6] | rec[7] << 8, rsize = rec[8] | rec[9] << 8, off = NSA$C_MSG_HDR_LENGTH, k;
        char when[24] = "", user[40] = "", term[40] = "", rnode[64] = "", ruser[40] = "", rfull[128] = "";
        unsigned pid = 0, status = 0;
        int incl = -1;   /* does a packet's size include its header? decided per record */
        total++;
        if (type != NSA$C_MSG_LOGFAIL && type != NSA$C_MSG_BREAKIN) continue;
        if (!dumped) {
            unsigned i;
            printf("  [raw] rsz %u record_size %u packets %u:", rlen, rsize, npk);
            for (i = 0; i < rlen && i < 96; i++) printf("%s%02X", i % 16 ? " " : "\n   ", rec[i]);
            printf("\n");
            dumped = 1;
        }
        /* Try "size excludes the header" first; if the packets then do not end at the
           record's end, the other reading is the right one. */
        {
            unsigned o = off, c;
            for (c = 0; c < npk && o + 4 <= rlen; c++) o += 4 + (rec[o] | rec[o + 1] << 8);
            incl = (o == rlen || o == rsize) ? 0 : 1;
        }
        for (k = 0; k < npk && off + 4 <= rlen; k++) {
            unsigned psize = rec[off] | rec[off + 1] << 8, ptype = rec[off + 2] | rec[off + 3] << 8;
            unsigned dlen = incl ? psize - 4 : psize;
            const unsigned char *d = rec + off + 4;
            if (off + 4 + dlen > rlen) break;
            switch (ptype) {
            case NSA$C_PKT_TIME_STAMP: if (dlen >= 8) vmstime(d, when); break;
            case NSA$C_PKT_USERNAME: text(d, dlen, user, sizeof user); break;
            case NSA$C_PKT_TERMINAL: text(d, dlen, term, sizeof term); break;
            case NSA$C_PKT_REMOTE_NODENAME: text(d, dlen, rnode, sizeof rnode); break;
            case NSA$C_PKT_REMOTE_USERNAME: text(d, dlen, ruser, sizeof ruser); break;
            case NSA$C_PKT_REMOTE_NODE_FULLNAME: text(d, dlen, rfull, sizeof rfull); break;
            case NSA$C_PKT_PROCESS_ID: if (dlen >= 4) memcpy(&pid, d, 4); break;
            case NSA$C_PKT_FINAL_STATUS: if (dlen >= 4) memcpy(&status, d, 4); break;
            }
            off += 4 + dlen;
        }
        printf("  %-8s %-10s %s user \"%s\" term \"%s\" rnode \"%s\" ruser \"%s\" rfull \"%s\" pid %08X status %%X%08X (size %s header)\n",
               type == NSA$C_MSG_LOGFAIL ? "LOGFAIL" : "BREAKIN", subtype(sub), when, user, term, rnode, ruser, rfull,
               pid, status, incl ? "includes" : "excludes");
        shown++;
    }
    report("end of journal", st);
    printf("  %u records, %u LOGFAIL/BREAKIN\n", total, shown);
    sys$close(&fab);
    return 1;
}
