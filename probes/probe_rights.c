/* probe_rights.c - can we enumerate the rights database, and its holders? (read-only)

   Usage: probe_rights [identifier]

   1. $IDTOASC with id -1 (wildcard) walks every identifier; counts general (bit 31 set)
      and UIC identifiers and prints the first few of each.
   2. $FIND_HELD for this process's UIC: the identifiers we hold.
   3. With an argument, $ASCTOID then $FIND_HOLDER: the holders of that identifier.

   Answers: does wildcard enumeration work for a non-SYSPRV caller, and what does the
   rights database look like to one. Changes nothing. */
#include <stdlib.h>
#include <ssdef.h>
#include <jpidef.h>
#include "probe_common.h"

static void show_id(unsigned int id, unsigned int attrib)
{
    char name[64]; unsigned short len = 0; unsigned int resid = 0, at = 0, ctx = 0, st;
    struct dsc$descriptor_s d;
    desc_set(&d, name, sizeof name - 1);
    st = sys$idtoasc(id, &len, &d, &resid, &at, &ctx);
    if (st & 1) { name[len] = '\0'; } else strcpy(name, "?");
    sys$finish_rdb(&ctx);
    printf("    %%X%08X %-32s attrib %%X%08X\n", id, name, attrib);
}

int main(int argc, char **argv)
{
    unsigned int ctx = 0, id, resid, attrib, st, uic = 0, iosb[2];
    unsigned int general = 0, uicids = 0;
    char name[64]; unsigned short len;
    struct dsc$descriptor_s d;
    ile3 items[2];

    printf("probe_rights: $IDTOASC wildcard\n");
    for (;;) {
        desc_set(&d, name, sizeof name - 1);
        len = 0; resid = attrib = 0;
        st = sys$idtoasc((unsigned int) -1, &len, &d, &resid, &attrib, &ctx);
        if (!(st & 1)) break;
        name[len] = '\0';
        if (resid & 0x80000000u) {
            if (++general <= 5) printf("    general %%X%08X %-32s attrib %%X%08X\n", resid, name, attrib);
        } else {
            if (++uicids <= 5) printf("    uic     %%X%08X %s\n", resid, name);
        }
    }
    sys$finish_rdb(&ctx);
    report("end of enumeration", st);
    printf("  general identifiers: %u, UIC identifiers: %u\n", general, uicids);
    if (st != SS$_NOSUCHID) printf("  NOTE: ended with something other than NOSUCHID\n");

    printf("probe_rights: $FIND_HELD for our UIC\n");
    ile3_set(&items[0], JPI$_UIC, &uic, 4, 0); ile3_end(&items[1]);
    st = sys$getjpiw(0, 0, 0, items, iosb, 0, 0);
    if (st & 1) st = iosb[0];
    report("$GETJPI UIC", st);
    {
        unsigned int holder[2]; holder[0] = uic; holder[1] = 0; ctx = 0;
        while ((st = sys$find_held((void *) holder, &id, &attrib, &ctx)) & 1)
            show_id(id, attrib);
        sys$finish_rdb(&ctx);
        report("end of held list", st);
    }

    if (argc > 1) {
        unsigned int holder[2], target;
        printf("probe_rights: $FIND_HOLDER for %s\n", argv[1]);
        desc_set(&d, argv[1], (unsigned short) strlen(argv[1]));
        st = sys$asctoid(&d, &target, &attrib);
        report("$ASCTOID", st);
        if (st & 1) {
            unsigned int n = 0; ctx = 0;
            while ((st = sys$find_holder(target, (void *) holder, &attrib, &ctx)) & 1)
                if (++n <= 20) printf("    holder UIC [%o,%o] attrib %%X%08X\n",
                                      holder[0] >> 16, holder[0] & 0xFFFF, attrib);
            sys$finish_rdb(&ctx);
            report("end of holder list", st);
            printf("  holders: %u\n", n);
        }
    }
    return 1;
}
