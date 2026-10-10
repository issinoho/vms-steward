/* st_route.c - path matching and input validation, no I/O. */
#include <ctype.h>
#include <string.h>
#include "st_http.h"
#include "st_route.h"

int st_route_match(const char *pat, const char *path,
                   char args[][ST_ARG_MAX], int maxargs, int *nargs)
{
    int n = 0, bad = 0;
    *nargs = 0;
    for (;;) {
        const char *pe, *se;
        if (*pat != *path) return 0;
        if (*pat == '\0') break;
        if (*pat != '/') return 0;
        pat++; path++;
        pe = strchr(pat, '/'); if (!pe) pe = pat + strlen(pat);
        se = strchr(path, '/'); if (!se) se = path + strlen(path);
        if (*pat == '{') {
            if (se == path || n >= maxargs) return 0;   /* empty segment never matches */
            if (st_pct_decode(path, (size_t) (se - path), args[n], ST_ARG_MAX, 0) ||
                strchr(args[n], '/'))
                bad = 1;
            n++;
        } else if ((size_t) (pe - pat) != (size_t) (se - path) ||
                   memcmp(pat, path, (size_t) (pe - pat))) {
            return 0;
        }
        pat = pe;
        path = se;
    }
    *nargs = n;
    return bad ? -1 : 1;
}

int st_valid_username(const char *in, char out[ST_USERNAME_MAX + 1])
{
    size_t i, n = strlen(in);
    if (n == 0 || n > ST_USERNAME_MAX) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) in[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char) (c - 'a' + 'A');
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'))
            return 0;
        out[i] = (char) c;
    }
    out[n] = '\0';
    return 1;
}

int st_valid_ident(const char *in, char out[ST_IDENT_MAX + 1])
{
    size_t i, n = strlen(in);
    int nondigit = 0;
    if (n == 0 || n > ST_IDENT_MAX) return 0;
    for (i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z') c = (char) (c - 'a' + 'A');
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$')) return 0;
        if (c < '0' || c > '9') nondigit = 1;
        out[i] = c;
    }
    out[n] = '\0';
    return nondigit;
}

int st_valid_filter(const char *in, char out[ST_IDENT_MAX + 1])
{
    size_t i, n = strlen(in);
    if (n > ST_IDENT_MAX) return 0;
    for (i = 0; i < n; i++) {
        char c = in[i];
        if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') return 0;
        if (c >= 'a' && c <= 'z') c = (char) (c - 'a' + 'A');
        out[i] = c;
    }
    out[n] = '\0';
    return 1;
}

static char up(char c) { return (c >= 'a' && c <= 'z') ? (char) (c - 'a' + 'A') : c; }

int st_wild_match(const char *p, const char *s)
{
    const char *star = NULL, *resume = NULL;
    while (*s) {
        if (*p == '*') { star = p++; resume = s; continue; }
        if (*p && (*p == '%' || up(*p) == up(*s))) { p++; s++; continue; }
        if (!star) return 0;
        p = star + 1;
        s = ++resume;
    }
    while (*p == '*') p++;
    return *p == '\0';
}

static int contains(const char *hay, const char *needle)
{
    size_t i, j, n = strlen(needle);
    if (!hay) return 0;
    for (i = 0; hay[i]; i++) {
        for (j = 0; j < n && hay[i + j] && up(hay[i + j]) == up(needle[j]); j++) ;
        if (j == n) return 1;
    }
    return n == 0;
}

int st_filter_match(const char *filter, const char *name, const char *other)
{
    if (!filter || !*filter) return 1;
    if (strchr(filter, '*') || strchr(filter, '%')) return st_wild_match(filter, name);
    return contains(name, filter) || contains(other, filter);
}

int st_valid_ip(const char *in)
{
    size_t i, n = strlen(in);
    if (n == 0 || n > 45) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) in[i];
        if (!(isxdigit(c) || c == '.' || c == ':')) return 0;
    }
    return 1;
}

void st_hex(const unsigned char *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = '\0';
}

static int hv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int st_unhex(const char *in, unsigned char *p, size_t n)
{
    size_t i;
    if (strlen(in) != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        int hi = hv(in[2 * i]), lo = hv(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        p[i] = (unsigned char) (hi * 16 + lo);
    }
    return 1;
}

int st_ct_equal(const void *a, const void *b, size_t n)
{
    const volatile unsigned char *x = a, *y = b;
    unsigned char d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (unsigned char) (x[i] ^ y[i]);
    return d == 0;
}
