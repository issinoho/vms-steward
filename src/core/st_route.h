/* st_route.h - path matching and input validation, no I/O. */
#ifndef ST_ROUTE_H
#define ST_ROUTE_H

#include <stddef.h>

#define ST_ARG_MAX      256
#define ST_ROUTE_ARGS   4

/* Match a percent-encoded request path against a pattern such as
   "/api/v1/users/{u}/identifiers". Each {name} captures one whole segment,
   percent-decoded (a decoded '/' or NUL is refused). Returns 1 on a match, 0 if the
   path does not fit the pattern, -1 if it fits but a segment is badly encoded. */
int st_route_match(const char *pattern, const char *path,
                   char args[][ST_ARG_MAX], int maxargs, int *nargs);

/* OpenVMS usernames: 1-12 characters from A-Z, 0-9, '_' and '$', case-insensitive.
   Writes the upper-case form to out[13]. Returns 1 if valid. Every username from a
   request goes through this before reaching $ACM or $PERSONA_CREATE: persona creation
   takes a lowercase name as given (docs/PHASE0.md). */
#define ST_USERNAME_MAX 12
int st_valid_username(const char *in, char out[ST_USERNAME_MAX + 1]);

/* Rights identifier names: 1-31 characters from A-Z, 0-9, '_' and '$', with at least
   one that is not a digit, case-insensitive. Writes the upper-case form to out[32].
   Returns 1 if valid. */
#define ST_IDENT_MAX 31
int st_valid_ident(const char *in, char out[ST_IDENT_MAX + 1]);

/* A search filter as the list endpoints take it: up to 31 characters, printable ASCII
   with no quotes or backslashes. Writes the upper-case form to out[32]. Returns 1 if
   valid. */
int st_valid_filter(const char *in, char out[ST_IDENT_MAX + 1]);

/* Does s match pattern? '*' matches any run of characters and '%' exactly one, as in
   DCL; anything else matches itself, ignoring case. Iterative: no recursion, and
   linear in practice for the short strings it sees. */
int st_wild_match(const char *pattern, const char *s);
/* The filter rule shared by the list endpoints: with '*' or '%' it is a wildcard on
   name; otherwise a case-insensitive substring of name or of other (may be NULL). */
int st_filter_match(const char *filter, const char *name, const char *other);

/* A client address as lighttpd reports it (IPv4 or IPv6 text), safe to hand to
   $ACM as the remote host name. Returns 1 if valid. */
int st_valid_ip(const char *in);

/* Lower-case hex of n bytes into out[2n+1]. */
void st_hex(const unsigned char *p, size_t n, char *out);
/* Parse exactly 2n hex digits into p[n]. Returns 1 if valid. */
int  st_unhex(const char *in, unsigned char *p, size_t n);
/* Constant-time comparison of two equal-length byte strings: 1 if equal. */
int  st_ct_equal(const void *a, const void *b, size_t n);

#endif
