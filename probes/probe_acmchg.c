/* probe_acmchg.c - which item list does $ACM CHANGE_PASSWORD accept? (non-dialogue)

   Usage: probe_acmchg <user>

   probe_password CHANGE got SS$_INSFARG from $ACMW itself: the call was refused before
   any password was looked at. This tries item-list variants with a deliberately
   wrong, made-up current password, so nothing can change. A variant that gets past
   the argument check comes back with an authentication failure in the ACMESB
   instead. Each attempt names a client from 192.0.2.0/24 (RFC 5737), so any
   intrusion record is charged to a documentation address, not to a real one. */
#include <stdlib.h>
#include <ssdef.h>
#include <utcblkdef.h>
#include <acmedef.h>
#include "probe_common.h"

static void attempt(const char *label, const char *user, int variant)
{
    static const char wrong[] = "not-the-password-x1";
    static const char newpw[] = "also-not-a-real-password-x2";
    char host[16];
    struct _acmesb sb;
    unsigned int ltype = ACME$K_NETWORK, st, flags = 0;
    ile3 it[10];
    int n = 0;

    snprintf(host, sizeof host, "192.0.2.%d", 50 + variant);
    memset(&sb, 0, sizeof sb);
    ile3_set(&it[n++], ACME$_PRINCIPAL_NAME_IN, (void *) user, (unsigned short) strlen(user), 0);
    ile3_set(&it[n++], ACME$_PASSWORD_1, (void *) wrong, sizeof wrong - 1, 0);
    ile3_set(&it[n++], ACME$_NEW_PASSWORD_1, (void *) newpw, sizeof newpw - 1, 0);
    if (variant >= 1) ile3_set(&it[n++], ACME$_LOGON_TYPE, &ltype, 4, 0);
    if (variant >= 1) ile3_set(&it[n++], ACME$_REMOTE_HOST_NAME, host, (unsigned short) strlen(host), 0);
    if (variant >= 1) ile3_set(&it[n++], ACME$_REMOTE_USERNAME, "STEWARD", 7, 0);
    if (variant == 2) ile3_set(&it[n++], ACME$_NEW_PASSWORD_FLAGS, &flags, 4, 0);
    ile3_end(&it[n]);
    st = sys$acmw(0, ACME$_FC_CHANGE_PASSWORD, 0, (void *) it, &sb, 0, 0);
    printf("%s\n", label);
    report("  $ACMW", st);
    if (st & 1) {
        report("  ACMESB status", sb.acmesb$l_status);
        if (sb.acmesb$l_secondary_status) report("  ACMESB secondary", sb.acmesb$l_secondary_status);
    }
}

int main(int argc, char **argv)
{
    char user[13];
    size_t i;
    if (argc != 2) { printf("usage: probe_acmchg <user>\n"); return 1; }
    for (i = 0; argv[1][i] && i < 12; i++)
        user[i] = (char) ((argv[1][i] >= 'a' && argv[1][i] <= 'z') ? argv[1][i] - 32 : argv[1][i]);
    user[i] = '\0';
    attempt("0: principal, password, new password", user, 0);
    attempt("1: + logon type, remote host, remote user", user, 1);
    attempt("2: + new password flags", user, 2);
    return 1;
}
