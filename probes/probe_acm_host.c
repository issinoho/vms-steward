/* probe_acm_host.c - can we make an intrusion record name the browser, not the service?

   Usage: probe_acm_host <username>
   The password comes from the process logical STEWARD_PROBE_PW, as in probe_acm. Run
   it with a WRONG password: the point is the intrusion record each failure leaves.

   Phase 0 showed a failed $ACM is recorded against the calling process
   ("X86VMS::IAIN"), so every web login would share one record. Each variant here
   fails once while describing a different client from the 192.0.2.0/24 documentation
   range (RFC 5737), so SHOW INTRUSION afterwards shows which items ACM uses:
     .11  REMOTE_HOST_NAME "192.0.2.11", logon type NETWORK
     .12  as .11, plus REMOTE_USERNAME "steward"
     .13  as .12, logon type REMOTE instead of NETWORK
     .14  as .12, plus REMOTE_HOST_ADDRESS (4 bytes) + _TYPE (IPv4)
   A 4-byte IPv4 address is refused by the VMS ACME with BADBUFLEN in the ACMESB, even
   with the type given as a longword (2026-10-10).
   Leaves one intrusion record per variant (they expire on their own). */
#include <stdlib.h>
#include <ssdef.h>
#include <lnmdef.h>
#include <utcblkdef.h>   /* acmedef.h uses utcblk without including it */
#include <acmedef.h>
#include "probe_common.h"

static char pw[256];

static int get_pw(void)
{
    struct dsc$descriptor_s tab, nam;
    unsigned short len = 0;
    unsigned int st;
    ile3 items[2];
    desc_set(&tab, "LNM$PROCESS", 11);
    desc_set(&nam, "STEWARD_PROBE_PW", 16);
    ile3_set(&items[0], LNM$_STRING, pw, sizeof pw - 1, &len);
    ile3_end(&items[1]);
    st = sys$trnlnm(0, &tab, &nam, 0, items);
    if (!(st & 1)) { report("$TRNLNM STEWARD_PROBE_PW", st); return 0; }
    pw[len] = '\0';
    return 1;
}

static void attempt(const char *user, unsigned char last, int with_addr, int with_name,
                    int with_ruser, unsigned int ltype)
{
    struct _acmesb sb;
    unsigned char addr[4];
    /* A longword: the header's comment says 16-bit, its diagram shows 32 bits, and a
       2-byte buffer is refused with BADBUFLEN before the password is looked at. */
    unsigned int atype = ACMEHAT$K_IP_V4;
    char host[16];
    ile3 items[8];
    int n = 0;
    unsigned int st;

    addr[0] = 192; addr[1] = 0; addr[2] = 2; addr[3] = last;   /* network byte order */
    sprintf(host, "192.0.2.%u", last);
    memset(&sb, 0, sizeof sb);
    ile3_set(&items[n++], ACME$_PRINCIPAL_NAME_IN, (void *) user, (unsigned short) strlen(user), 0);
    ile3_set(&items[n++], ACME$_PASSWORD_1, pw, (unsigned short) strlen(pw), 0);
    ile3_set(&items[n++], ACME$_LOGON_TYPE, &ltype, 4, 0);
    if (with_addr) {
        ile3_set(&items[n++], ACME$_REMOTE_HOST_ADDRESS_TYPE, &atype, 4, 0);
        ile3_set(&items[n++], ACME$_REMOTE_HOST_ADDRESS, addr, 4, 0);
    }
    if (with_name) ile3_set(&items[n++], ACME$_REMOTE_HOST_NAME, host, (unsigned short) strlen(host), 0);
    if (with_ruser) ile3_set(&items[n++], ACME$_REMOTE_USERNAME, "steward", 7, 0);
    ile3_end(&items[n]);

    printf("%s addr=%d name=%d ruser=%d logon_type=%u\n", host, with_addr, with_name,
           with_ruser, ltype);
    st = sys$acmw(0, ACME$_FC_AUTHENTICATE_PRINCIPAL, 0, items, &sb, 0, 0);
    report("$ACMW", st);
    report("acmesb status", sb.acmesb$l_status);
    report("acmesb secondary", sb.acmesb$l_secondary_status);
}

int main(int argc, char **argv)
{
    if (argc < 2) { printf("usage: probe_acm_host <username>\n"); return 1; }
    if (!get_pw()) return 1;
    attempt(argv[1], 11, 0, 1, 0, ACME$K_NETWORK);
    attempt(argv[1], 12, 0, 1, 1, ACME$K_NETWORK);
    attempt(argv[1], 13, 0, 1, 1, ACME$K_REMOTE);
    attempt(argv[1], 14, 1, 1, 1, ACME$K_NETWORK);
    memset(pw, 0, sizeof pw);
    return 1;
}
