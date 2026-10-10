/* probe_selfuai.c - can an unprivileged persona read its own UAF record? (read-only)

   Usage: probe_selfuai <username>

   The service account will hold IMPERSONATE but not SYSPRV, so it cannot $GETUAI
   other users. After $ACM accepts a password, Steward must still check expiry
   (non-dialogue $ACM accepts an expired one: PHASE0 #5), and the plan is to do it
   as the user: assume their persona and $GETUAI their own record. This checks that
   works, and prints the fields the check needs: UAI$_FLAGS, UAI$_PWD_DATE,
   UAI$_PWD2_DATE and UAI$_PWD_LIFETIME (quadwords, printed in hex), and UAI$_OWNER.
   Changes nothing. */
#include <stdlib.h>
#include <ssdef.h>
#include <uaidef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static void getuai(const char *when, const char *user)
{
    struct dsc$descriptor_s d;
    unsigned int flags = 0, st;
    unsigned int pwd[2] = {0, 0}, pwd2[2] = {0, 0}, life[2] = {0, 0};
    char owner[33]; unsigned short olen = 0;
    ile3 items[6];
    char label[64];

    desc_set(&d, user, (unsigned short) strlen(user));
    ile3_set(&items[0], UAI$_FLAGS, &flags, 4, 0);
    ile3_set(&items[1], UAI$_PWD_DATE, pwd, 8, 0);
    ile3_set(&items[2], UAI$_PWD2_DATE, pwd2, 8, 0);
    ile3_set(&items[3], UAI$_PWD_LIFETIME, life, 8, 0);
    ile3_set(&items[4], UAI$_OWNER, owner, 32, &olen);
    ile3_end(&items[5]);
    st = sys$getuai(0, 0, &d, items, 0, 0, 0);
    sprintf(label, "[%s] $GETUAI %s", when, user);
    report(label, st);
    if (st & 1)
        printf("    flags %%X%08X pwd_date %%X%08X%08X pwd2_date %%X%08X%08X lifetime %%X%08X%08X owner \"%.*s\"\n",
               flags, pwd[1], pwd[0], pwd2[1], pwd2[0], life[1], life[0],
               olen ? (unsigned char) owner[0] : 0, owner + 1);
}

int main(int argc, char **argv)
{
    unsigned int persona = 0, natural = ISS$C_ID_NATURAL, st;
    struct dsc$descriptor_s d;

    if (argc < 2) { printf("usage: probe_selfuai <username>\n"); return 1; }
    getuai("natural", argv[1]);
    desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
    st = sys$persona_create(&persona, &d, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&persona, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    if (st & 1) {
        getuai("persona", argv[1]);   /* its own record */
        getuai("persona", "SYSTEM");  /* someone else's, for contrast */
    }
    report("$PERSONA_ASSUME natural", sys$persona_assume(&natural, 0, 0, 0));
    report("$PERSONA_DELETE", sys$persona_delete(&persona));
    return 1;
}
