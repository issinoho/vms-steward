/* probe_sndopr.c - Phase 14b: does OPCOM start a new operator log for a $SNDOPR
   OPC$_RQ_LOGI request from a process with OPER but no operator terminal?

   CHANGES THE SYSTEM: if OPCOM accepts it, the current OPERATOR.LOG is closed and a new
   version opened, as REPLY/LOG does. Run only with the user's go-ahead (PHASE14.md,
   question 3, 2026-10-17). Run with OPER and nothing else:

     $ SET PROCESS/PRIVILEGE=(NOALL,TMPMBX,NETMBX,OPER)
     $ RUN PROBE_SNDOPR

   The message is OPCDEF's old format, built with explicit offsets: type (byte 0,
   OPC$_RQ_LOGI = 2), target classes (bytes 1-3, 0), request id (bytes 4-7). OPCOM's
   reply comes to a mailbox: printed as hex, with its status word (offset 2). */
#include <stdio.h>
#include <string.h>
#include <descrip.h>
#include <iodef.h>
#include <starlet.h>
#include <lib$routines.h>

int main(void)
{
    unsigned char msg[8], reply[512];
    unsigned short chan = 0, iosb[4];
    struct dsc$descriptor_s d;
    unsigned int st, i, ef = 0;
    float secs = 2.0f;
    int type = 4;   /* LIB$K_IEEE_S (NOTES.md) */

    memset(msg, 0, sizeof msg);
    msg[0] = 2;            /* OPC$_RQ_LOGI */
    msg[4] = 0x14;         /* request id 0x0B14: anything */
    msg[5] = 0x0B;
    d.dsc$w_length = sizeof msg;
    d.dsc$b_dtype = DSC$K_DTYPE_T;
    d.dsc$b_class = DSC$K_CLASS_S;
    d.dsc$a_pointer = (char *) msg;

    st = sys$crembx(0, &chan, sizeof reply, sizeof reply * 2, 0xFF00, 0, 0, 0, 0);
    printf("crembx %08X\n", st);
    if (!(st & 1)) return st;
    st = sys$sndopr(&d, chan);
    printf("sndopr %08X\n", st);
    if (!(st & 1)) return 1;
    lib$get_ef(&ef);
    memset(iosb, 0, sizeof iosb);
    st = sys$qio(ef, chan, IO$_READVBLK, (void *) iosb, 0, 0, reply, sizeof reply, 0, 0, 0, 0);
    printf("qio %08X\n", st);
    for (i = 0; i < 30 && !iosb[0]; i++) lib$wait(&secs, 0, &type);   /* up to 60 s, checked each 2 */
    if (!iosb[0]) { printf("no reply\n"); sys$cancel(chan); return 1; }
    printf("reply iosb %04X len %u:", iosb[0], iosb[1]);
    for (i = 0; i < iosb[1] && i < 64; i++) printf(" %02X", reply[i]);
    printf("\nstatus word %04X\n", reply[2] | reply[3] << 8);
    return 1;
}
