/* st_crypto_openssl.c - st_plat_random and st_plat_sha256 over OpenSSL.

   Shared by both platforms. On OpenVMS this is SSL3$LIBCRYPTO_SHR32 (DECISIONS D3),
   checked against published vectors by probes/probe_crypto.c. */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "st_platform.h"

int st_plat_random(void *p, size_t n)
{
    return RAND_bytes(p, (int) n) == 1;
}

void st_plat_sha256(const void *p, size_t n, unsigned char out[32])
{
    unsigned int len = 32;
    EVP_Digest(p, n, out, &len, EVP_sha256(), NULL);
}
