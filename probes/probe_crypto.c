/* probe_crypto.c - the OpenSSL calls sessions need, from VSI C with 32-bit pointers.

   RAND_bytes for session ids, SHA-256 for the session key, HMAC-SHA256 for the CSRF
   token, each checked against a published vector (FIPS 180-2 "abc"; RFC 4231 test
   case 2). Linked against SSL3$LIBCRYPTO_SHR32 with the OPENSSL logical pointing at
   SSL3$INCLUDE, as vmsguard's build_vms.com does. Changes nothing. */
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static void hex(const unsigned char *p, unsigned int n, char *out)
{
    unsigned int i;
    for (i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
}

int main(void)
{
    unsigned char buf[32], md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    char h[2 * EVP_MAX_MD_SIZE + 1];
    int ok = 1, one;

    printf("probe_crypto: %s\n", OPENSSL_VERSION_TEXT);

    printf("  RAND_bytes(32)        %s\n", RAND_bytes(buf, sizeof buf) == 1 ? "OK" : (ok = 0, "FAIL"));

    EVP_Digest("abc", 3, md, &mdlen, EVP_sha256(), NULL);
    hex(md, mdlen, h);
    one = !strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ok &= one;
    printf("  SHA-256(\"abc\")        %s\n", one ? "OK" : "FAIL");

    HMAC(EVP_sha256(), "Jefe", 4, (const unsigned char *) "what do ya want for nothing?", 28,
         md, &mdlen);
    hex(md, mdlen, h);
    one = !strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    ok &= one;
    printf("  HMAC-SHA256 RFC 4231  %s\n", one ? "OK" : "FAIL");

    printf("probe_crypto: %s\n", ok ? "all OK" : "FAILED");
    return 1;
}
