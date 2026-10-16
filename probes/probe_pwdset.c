/* probe_pwdset.c - does $SETUAI refuse a password longer than UAI$C_MAX_PWD_LENGTH?

   Usage: probe_pwdset <username>

   CHANGES <username>'s PASSWORD, briefly: sets it with $SETUAI (UAI$_PASSWORD, as
   st_plat_user_set_password does) to 32, 33 and 64 characters, printing each status,
   and then sets it back to the password in the process logical STEWARD_PROBE_PW (so it
   is never on a command line). Run only on an account the user named for testing.
   The point: UAI$C_MAX_PWD_LENGTH is 32 on IA64 V8.4-2L3 and 64 on x86, and
   $HASH_PASSWORD takes any length (NOTES.md); does the system itself refuse 33? */
#include <stdlib.h>
#include <ssdef.h>
#include <uaidef.h>
#include <lnmdef.h>
#include "probe_common.h"

static unsigned int set_pw(const char *user, const char *pw, unsigned short len)
{
    struct dsc$descriptor_s du;
    ile3 it[2];
    desc_set(&du, user, (unsigned short) strlen(user));
    ile3_set(&it[0], UAI$_PASSWORD, (void *) pw, len, 0);
    ile3_end(&it[1]);
    return sys$setuai(0, 0, &du, it, 0, 0, 0);
}

int main(int argc, char **argv)
{
    static const unsigned short lens[] = { 32, 33, 64 };
    char pw[256], k[65];
    unsigned short pwlen = 0;
    struct dsc$descriptor_s tab, nam;
    ile3 it[2];
    unsigned int st;
    int i;
    if (argc < 2) { printf("usage: probe_pwdset <username>\n"); return 1; }
    desc_set(&tab, "LNM$PROCESS", 11);
    desc_set(&nam, "STEWARD_PROBE_PW", 16);
    ile3_set(&it[0], LNM$_STRING, pw, sizeof pw - 1, &pwlen);
    ile3_end(&it[1]);
    st = sys$trnlnm(0, &tab, &nam, 0, it);
    if (!(st & 1) || !pwlen) { printf("no STEWARD_PROBE_PW: nothing changed\n"); return 1; }
    printf("UAI$C_MAX_PWD_LENGTH %d\n", (int) UAI$C_MAX_PWD_LENGTH);
    memset(k, 'K', sizeof k);
    for (i = 0; i < 3; i++)
        printf("  $SETUAI length %2u  %s\n", lens[i], msg(set_pw(argv[1], k, lens[i])));
    st = set_pw(argv[1], pw, pwlen);
    printf("  restored             %s\n", msg(st));
    memset(pw, 0, sizeof pw);
    return 1;
}
