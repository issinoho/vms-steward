/* probe_modify.c - the Phase 3 modify services: who may use them, and how they behave.

   Usage: probe_modify <test-user> <test-identifier>
     e.g. probe_modify STEWARD_TEST STEWARD_TEST_ID

   CHANGES THE SYSTEM, ONLY THESE TWO NAMES (both approved by the user for testing,
   2026-10-10), AND PUTS EVERYTHING BACK:

   A. Under the test user's own persona (no privileges beyond its defaults):
        $SETUAI on its own owner field, and $ADD_IDENT. Expected: refused by OpenVMS.
   B. As the caller (a privileged work account):
        $SETUAI owner and one flag (DISWELCOME), read back, restore, read back;
        $ADD_IDENT the identifier, $ADD_HOLDER the test user, $FIND_HELD,
        $MOD_HOLDER (set RESOURCE on the holding), $MOD_IDENT (rename and back,
        set an attribute), $REM_HOLDER;
        then $ADD_HOLDER again and $REM_IDENT while still held, to see whether the
        holder record goes with it, as AUTHORIZE REMOVE/IDENTIFIER does.

   Refuses to run if the identifier already exists, so it never removes one it did
   not create. */
#include <stdlib.h>
#include <ssdef.h>
#include <prvdef.h>
#include <uaidef.h>
#include <kgbdef.h>
#include "probe_common.h"

#ifndef ISS$C_ID_NATURAL
#define ISS$C_ID_NATURAL 1
#endif

static const char *user;

static void owner_now(const char *who, char *out)
{
    char buf[32] = { 0 };
    unsigned short l = 0;
    struct dsc$descriptor_s d;
    ile3 it[2];
    desc_set(&d, who, (unsigned short) strlen(who));
    ile3_set(&it[0], UAI$_OWNER, buf, sizeof buf, &l);
    ile3_end(&it[1]);
    out[0] = '\0';
    if (sys$getuai(0, 0, &d, it, 0, 0, 0) & 1) {
        int n = (unsigned char) buf[0];
        memcpy(out, buf + 1, n);
        out[n] = '\0';
    }
}

/* UAI$_OWNER is a fixed 32-byte field: a length byte and up to 31 characters. A
   shorter buffer was refused with BADPARAM (first run, 2026-10-10). */
static unsigned int set_owner(const char *who, const char *owner)
{
    char buf[32];
    struct dsc$descriptor_s d;
    ile3 it[2];
    size_t n = strlen(owner);
    if (n > 31) n = 31;
    memset(buf, ' ', sizeof buf);
    buf[0] = (char) n;
    memcpy(buf + 1, owner, n);
    desc_set(&d, who, (unsigned short) strlen(who));
    ile3_set(&it[0], UAI$_OWNER, buf, sizeof buf, 0);
    ile3_end(&it[1]);
    return sys$setuai(0, 0, &d, it, 0, 0, 0);
}

static unsigned int flags_now(const char *who)
{
    unsigned int f = 0;
    struct dsc$descriptor_s d;
    ile3 it[2];
    desc_set(&d, who, (unsigned short) strlen(who));
    ile3_set(&it[0], UAI$_FLAGS, &f, 4, 0);
    ile3_end(&it[1]);
    sys$getuai(0, 0, &d, it, 0, 0, 0);
    return f;
}

static unsigned int set_flags(const char *who, unsigned int f)
{
    struct dsc$descriptor_s d;
    ile3 it[2];
    desc_set(&d, who, (unsigned short) strlen(who));
    ile3_set(&it[0], UAI$_FLAGS, &f, 4, 0);
    ile3_end(&it[1]);
    return sys$setuai(0, 0, &d, it, 0, 0, 0);
}

static unsigned int uic_of(const char *who)
{
    unsigned int uic = 0;
    struct dsc$descriptor_s d;
    ile3 it[2];
    desc_set(&d, who, (unsigned short) strlen(who));
    ile3_set(&it[0], UAI$_UIC, &uic, 4, 0);
    ile3_end(&it[1]);
    sys$getuai(0, 0, &d, it, 0, 0, 0);
    return uic;
}

/* Does the holder hold id, and with which attributes? */
static int holds(unsigned int uic, unsigned int id, unsigned int *attrib)
{
    unsigned int holder[2], got, a, ctx = 0, st;
    int found = 0;
    holder[0] = uic; holder[1] = 0;
    while ((st = sys$find_held((void *) holder, &got, &a, &ctx)) & 1)
        if (got == id) { found = 1; *attrib = a; }
    sys$finish_rdb(&ctx);
    return found;
}

int main(int argc, char **argv)
{
    struct dsc$descriptor_s idd, d2;
    char name2[40], owner[40], ident[32];
    unsigned int st, id = 0, attrib = 0, uic, f0, holder[2];
    unsigned int imp[2] = { PRV$M_DETACH, 0 };
    unsigned int ph = 0;
    size_t i;

    if (argc != 3) { printf("usage: probe_modify <test-user> <test-identifier>\n"); return 1; }
    user = argv[1];
    /* The C RTL lowercases argv (NOTES.md); OpenVMS names are upper case. */
    for (i = 0; argv[1][i]; i++) if (argv[1][i] >= 'a' && argv[1][i] <= 'z') argv[1][i] -= 32;
    for (i = 0; argv[2][i] && i < 31; i++) ident[i] = (char) ((argv[2][i] >= 'a' && argv[2][i] <= 'z') ? argv[2][i] - 32 : argv[2][i]);
    ident[i] = '\0';
    desc_set(&idd, ident, (unsigned short) strlen(ident));
    if (sys$asctoid(&idd, &id, &attrib) & 1) {
        printf("probe_modify: %s already exists; not touching it\n", ident);
        return 1;
    }
    uic = uic_of(user);
    printf("probe_modify: user %s [%o,%o], identifier %s\n", user, uic >> 16, uic & 0xFFFF, ident);

    printf("A. as %s's own persona\n", user);
    sys$setprv(1, (void *) imp, 0, 0);
    desc_set(&d2, user, (unsigned short) strlen(user));
    st = sys$persona_create(&ph, &d2, 0, 0, 0);
    report("$PERSONA_CREATE", st);
    if (!(st & 1)) return 1;
    st = sys$persona_assume(&ph, 0, 0, 0);
    report("$PERSONA_ASSUME", st);
    owner_now(user, owner);
    report("$SETUAI own OWNER", set_owner(user, "should not change"));
    id = 0;
    report("$ADD_IDENT", sys$add_ident(&idd, 0, 0, &id));
    {
        unsigned int nat = ISS$C_ID_NATURAL;
        report("revert to natural", sys$persona_assume(&nat, 0, 0, 0));
    }
    sys$persona_delete(&ph);
    {
        char now[40];
        owner_now(user, now);
        printf("  owner unchanged: %s (\"%s\")\n", strcmp(now, owner) ? "NO" : "yes", now);
        printf("  identifier absent: %s\n", (sys$asctoid(&idd, &id, &attrib) & 1) ? "NO" : "yes");
    }

    printf("B. as the caller\n");
    owner_now(user, owner);
    report("$SETUAI OWNER", set_owner(user, "steward probe_modify"));
    owner_now(user, name2);
    printf("  read back: \"%s\"\n", name2);
    report("$SETUAI OWNER restore", set_owner(user, owner));
    owner_now(user, name2);
    printf("  restored: %s (\"%s\")\n", strcmp(name2, owner) ? "NO" : "yes", name2);

    f0 = flags_now(user);
    report("$SETUAI FLAGS +DISWELCOM", set_flags(user, f0 | UAI$M_DISWELCOM));
    printf("  read back %%X%08X (was %%X%08X)\n", flags_now(user), f0);
    report("$SETUAI FLAGS restore", set_flags(user, f0));
    printf("  restored: %s\n", flags_now(user) == f0 ? "yes" : "NO");

    id = 0;
    st = sys$add_ident(&idd, 0, 0, &id);
    report("$ADD_IDENT (value chosen by OS)", st);
    if (!(st & 1)) return 1;
    printf("  value %%X%08X\n", id);
    holder[0] = uic; holder[1] = 0;
    report("$ADD_HOLDER", sys$add_holder(id, (void *) holder, 0));
    report("$ADD_HOLDER again", sys$add_holder(id, (void *) holder, 0));
    printf("  held: %s\n", holds(uic, id, &attrib) ? "yes" : "NO");
    report("$MOD_HOLDER set RESOURCE", sys$mod_holder(id, (void *) holder, KGB$M_RESOURCE, 0));
    attrib = 0;
    holds(uic, id, &attrib);
    printf("  holding attributes %%X%08X (identifier without RESOURCE)\n", attrib);
    report("$MOD_IDENT set RESOURCE", sys$mod_ident(id, KGB$M_RESOURCE, 0, 0, 0));
    report("$MOD_HOLDER set RESOURCE", sys$mod_holder(id, (void *) holder, KGB$M_RESOURCE, 0));
    attrib = 0;
    holds(uic, id, &attrib);
    printf("  holding attributes %%X%08X (identifier with RESOURCE)\n", attrib);
    report("$MOD_IDENT clear RESOURCE", sys$mod_ident(id, 0, KGB$M_RESOURCE, 0, 0));
    attrib = 0;
    holds(uic, id, &attrib);
    printf("  holding attributes %%X%08X (after clearing it on the identifier)\n", attrib);

    snprintf(name2, sizeof name2, "%.28s_R", ident);
    desc_set(&d2, name2, (unsigned short) strlen(name2));
    report("$MOD_IDENT rename", sys$mod_ident(id, 0, 0, &d2, 0));
    {
        unsigned int got = 0, a = 0;
        printf("  %s now resolves: %s\n", name2, (sys$asctoid(&d2, &got, &a) & 1) && got == id ? "yes" : "NO");
    }
    report("$MOD_IDENT rename back", sys$mod_ident(id, 0, 0, &idd, 0));
    report("$MOD_IDENT set NOACCESS", sys$mod_ident(id, KGB$M_NOACCESS, 0, 0, 0));
    {
        unsigned int got = 0, a = 0;
        sys$asctoid(&idd, &got, &a);
        printf("  identifier attributes %%X%08X\n", a);
    }
    report("$REM_HOLDER", sys$rem_holder(id, (void *) holder));
    report("$REM_HOLDER again", sys$rem_holder(id, (void *) holder));
    printf("  held: %s\n", holds(uic, id, &attrib) ? "YES" : "no");

    report("$ADD_HOLDER (for removal test)", sys$add_holder(id, (void *) holder, 0));
    {
        unsigned int saved = id, got = 0;
        report("$REM_IDENT while held", sys$rem_ident(saved));
        printf("  identifier gone: %s\n", (sys$asctoid(&idd, &got, &attrib) & 1) ? "NO" : "yes");
        printf("  holder record gone: %s\n", holds(uic, saved, &attrib) ? "NO (orphan)" : "yes");
    }
    return 1;
}
