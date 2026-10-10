/* probe_acm.c - can a detached service check a password with SYS$ACM, non-interactively?

   Usage: probe_acm <username>
   The password is read from the process logical name STEWARD_PROBE_PW, so it never
   appears on a command line or in a log. Define it just before the run and deassign it
   straight after:
       $ define/process/nolog STEWARD_PROBE_PW "..."
       $ probe_acm USERNAME
       $ deassign/process STEWARD_PROBE_PW

   Three calls to ACME$_FC_AUTHENTICATE_PRINCIPAL, all non-dialogue (no context):
     A. principal + password only
     B. as A, with ACME$_LOGON_TYPE = network (what a web login is)
     C. as B, with ACME$M_ACQUIRE_CREDENTIALS and ACME$_PERSONA_HANDLE_OUT
   Each prints the ACMESB status, secondary status and ACME status. Run it with a right
   password, a wrong one, a DISUSERed account and a pre-expired password, and check
   intrusion records (SHOW INTRUSION) after a wrong one.

   Answers: which privileges ACM needs for each form, whether it applies DISUSER,
   expiry and intrusion detection for a network logon type, and whether it can hand us
   the persona directly. Changes nothing beyond what a failed or successful login
   records (last-login times, intrusion records). */
#include <stdlib.h>
#include <ssdef.h>
#include <prvdef.h>
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

static void attempt(const char *label, const char *user, int logon_type, int creds)
{
    struct _acmesb sb;
    unsigned int func = ACME$_FC_AUTHENTICATE_PRINCIPAL, st, persona = 0;
    unsigned int ltype = ACME$K_NETWORK;
    unsigned short plen = 0;
    ile3 items[5];
    int n = 0;

    memset(&sb, 0, sizeof sb);
    ile3_set(&items[n++], ACME$_PRINCIPAL_NAME_IN, (void *) user, (unsigned short) strlen(user), 0);
    ile3_set(&items[n++], ACME$_PASSWORD_1, pw, (unsigned short) strlen(pw), 0);
    if (logon_type) ile3_set(&items[n++], ACME$_LOGON_TYPE, &ltype, 4, 0);
    if (creds) {
        func |= ACME$M_ACQUIRE_CREDENTIALS;
        ile3_set(&items[n++], ACME$_PERSONA_HANDLE_OUT, &persona, 4, &plen);
    }
    ile3_end(&items[n]);

    printf("%s\n", label);
    st = sys$acmw(0, func, 0, items, &sb, 0, 0);
    report("$ACMW", st);
    report("acmesb status", sb.acmesb$l_status);
    report("acmesb secondary", sb.acmesb$l_secondary_status);
    {   /* acmesb$l_acme_id is a struct (acmeid) of one longword */
        unsigned int acme_id;
        memcpy(&acme_id, &sb.acmesb$l_acme_id, 4);
        printf("  acme id %%X%08X, acme status %%X%08X\n", acme_id, sb.acmesb$l_acme_status);
    }
    if (creds && persona) {
        printf("  persona handle %%X%08X\n", persona);
        report("$PERSONA_DELETE", sys$persona_delete(&persona));
    }
}

int main(int argc, char **argv)
{
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    if (argc < 2) { printf("usage: probe_acm <username>\n"); return 1; }
    if (!get_pw()) return 1;
    report("$SETPRV IMPERSONATE", sys$setprv(1, (void *) imp, 0, 0));
    attempt("A. principal + password", argv[1], 0, 0);
    attempt("B. + logon type network", argv[1], 1, 0);
    attempt("C. + acquire credentials", argv[1], 1, 1);
    memset(pw, 0, sizeof pw);  /* exiting next; not a dead store we rely on */
    return 1;
}
