/* probe_pwdlen.c - how long may a password be on this system? (read-only)

   Usage: probe_pwdlen

   Prints UAI$C_MAX_PWD_LENGTH from this node's <uaidef.h> and then hashes passwords of
   1, 32, 33 and 64 characters with $HASH_PASSWORD (Purdy_S, a made-up username),
   printing each status. Nothing is stored: $HASH_PASSWORD only computes. The header
   says 64 on x86 E9.2-4 and 32 on IA64 V8.4-2L3; this shows whether the system service
   agrees. */
#include <uaidef.h>
#include "probe_common.h"

int main(void)
{
    static const int lens[] = { 1, 32, 33, 64, 65 };
    char pw[66];
    unsigned int hash[2], st;
    unsigned short salt = 0x1234;
    struct dsc$descriptor_s dp, du;
    int i;
    printf("UAI$C_MAX_PWD_LENGTH %d\n", (int) UAI$C_MAX_PWD_LENGTH);
    desc_set(&du, "PROBE_PWDLEN", 12);
    for (i = 0; i < (int) (sizeof lens / sizeof lens[0]); i++) {
        memset(pw, 'K', sizeof pw);
        desc_set(&dp, pw, (unsigned short) lens[i]);
        st = sys$hash_password(&dp, UAI$C_PURDY_S, salt, &du, (void *) hash);
        printf("  length %2d  %s\n", lens[i], msg(st));
    }
    memset(pw, 0, sizeof pw);
    return 1;
}
