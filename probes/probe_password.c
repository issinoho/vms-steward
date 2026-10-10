/* probe_password.c - how the two password paths behave (Phase 3). Run interactively
   by the user, never by Claude: it reads passwords from the terminal without echo, and
   no password ever appears on the command line, in a log or in this repository.

   Usage:  probe_password SET <user>      as an administrator: $SETUAI UAI$_PASSWORD
           probe_password CHANGE <user>   as the user would: $ACM CHANGE_PASSWORD,
                                          which needs the current password

   Only STEWARD_TEST and STEWARD_ADM are accepted (the test accounts approved for
   Phase 3). It prints the password date, the expiry flags and the hash algorithm
   before and after, so we learn what each path does to them, and whether the
   system's password policy (minimum length, history, dictionary) applies. */
#include <stdlib.h>
#include <ssdef.h>
#include <iodef.h>
#include <uaidef.h>
#include <utcblkdef.h>
#include <acmedef.h>
#include "probe_common.h"

static void read_noecho(const char *prompt, char *out, size_t outlen)
{
    unsigned short chan = 0, iosb[4] = { 0 };
    struct dsc$descriptor_s d;
    unsigned int st;
    desc_set(&d, "SYS$COMMAND", 11);
    out[0] = '\0';
    fflush(stdout);   /* the C RTL buffers; without this the prompt overwrote the last line */
    if (!(sys$assign(&d, &chan, 0, 0) & 1)) return;
    st = sys$qiow(0, chan, IO$_READPROMPT | IO$M_NOECHO, (void *) iosb, 0, 0,
                  out, (unsigned int) outlen - 1, 0, 0, (void *) prompt, (unsigned int) strlen(prompt));
    if ((st & 1) && (iosb[0] & 1)) out[iosb[1]] = '\0';
    else out[0] = '\0';
    sys$dassgn(chan);
    printf("\n");
}

static void show(const char *user, const char *when)
{
    unsigned int flags = 0, date[2] = { 0, 0 }, st;
    unsigned char alg = 0;
    struct dsc$descriptor_s d;
    char text[32] = { 0 };
    unsigned short tl = 0;
    struct dsc$descriptor_s td;
    ile3 it[4];
    desc_set(&d, user, (unsigned short) strlen(user));
    ile3_set(&it[0], UAI$_FLAGS, &flags, 4, 0);
    ile3_set(&it[1], UAI$_PWD_DATE, date, 8, 0);
    ile3_set(&it[2], UAI$_ENCRYPT, &alg, 1, 0);
    ile3_end(&it[3]);
    st = sys$getuai(0, 0, &d, it, 0, 0, 0);
    if (!(st & 1)) { report("$GETUAI", st); return; }
    if (date[0] == 0xFFFFFFFFu && date[1] == 0xFFFFFFFFu) strcpy(text, "(pre-expired)");
    else {
        desc_set(&td, text, sizeof text - 1);
        sys$asctim(&tl, &td, (void *) date, 0);
        text[tl] = '\0';
    }
    printf("  %-7s pwd_date %s, PWD_EXPIRED %d, algorithm %u\n", when, text,
           (flags & UAI$M_PWD_EXPIRED) != 0, alg);
}

int main(int argc, char **argv)
{
    char user[13], pw[80], pw2[80];
    size_t i;
    unsigned int st;

    if (argc != 3) { printf("usage: probe_password SET|CHANGE <user>\n"); return 1; }
    for (i = 0; argv[2][i] && i < 12; i++)
        user[i] = (char) ((argv[2][i] >= 'a' && argv[2][i] <= 'z') ? argv[2][i] - 32 : argv[2][i]);
    user[i] = '\0';
    if (strcmp(user, "STEWARD_TEST") && strcmp(user, "STEWARD_ADM")) {
        printf("probe_password: only STEWARD_TEST or STEWARD_ADM\n");
        return 1;
    }
    show(user, "before");

    if (argv[1][0] == 's' || argv[1][0] == 'S') {
        struct dsc$descriptor_s d;
        ile3 it[2];
        read_noecho("New password: ", pw, sizeof pw);
        read_noecho("Again: ", pw2, sizeof pw2);
        if (strcmp(pw, pw2) || !*pw) { printf("probe_password: they differ, or empty\n"); return 1; }
        desc_set(&d, user, (unsigned short) strlen(user));
        ile3_set(&it[0], UAI$_PASSWORD, pw, (unsigned short) strlen(pw), 0);
        ile3_end(&it[1]);
        st = sys$setuai(0, 0, &d, it, 0, 0, 0);
        report("$SETUAI UAI$_PASSWORD", st);
    } else {
        struct _acmesb sb;
        unsigned int ltype = ACME$K_NETWORK, pflags = 0;
        ile3 it[7];
        read_noecho("Current password: ", pw, sizeof pw);
        read_noecho("New password: ", pw2, sizeof pw2);
        memset(&sb, 0, sizeof sb);
        ile3_set(&it[0], ACME$_PRINCIPAL_NAME_IN, user, (unsigned short) strlen(user), 0);
        ile3_set(&it[1], ACME$_PASSWORD_1, pw, (unsigned short) strlen(pw), 0);
        ile3_set(&it[2], ACME$_NEW_PASSWORD_1, pw2, (unsigned short) strlen(pw2), 0);
        ile3_set(&it[3], ACME$_LOGON_TYPE, &ltype, 4, 0);
        ile3_set(&it[4], ACME$_REMOTE_USERNAME, "STEWARD", 7, 0);
        /* Required in non-dialogue mode: without it $ACMW says INSFARG (probe_acmchg). */
        ile3_set(&it[5], ACME$_NEW_PASSWORD_FLAGS, &pflags, 4, 0);
        ile3_end(&it[6]);
        st = sys$acmw(0, ACME$_FC_CHANGE_PASSWORD, 0, (void *) it, &sb, 0, 0);
        report("$ACMW CHANGE_PASSWORD", st);
        report("  ACMESB status", sb.acmesb$l_status);
        if (sb.acmesb$l_secondary_status) report("  ACMESB secondary", sb.acmesb$l_secondary_status);
    }
    memset(pw, 0, sizeof pw);
    memset(pw2, 0, sizeof pw2);
    show(user, "after");
    return 1;
}
