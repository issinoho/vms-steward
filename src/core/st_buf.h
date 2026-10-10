/* st_buf.h - growable byte buffers and secret scrubbing. */
#ifndef ST_BUF_H
#define ST_BUF_H

#include <stddef.h>

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    size_t limit;   /* 0 = unlimited; appends past it fail and set .overflow */
    int    overflow;
    int    oom;
} st_buf;

void st_buf_init(st_buf *b, size_t limit);
void st_buf_free(st_buf *b);
void st_buf_reset(st_buf *b);
int  st_buf_append(st_buf *b, const void *p, size_t n);
int  st_buf_puts(st_buf *b, const char *s);
int  st_buf_putc(st_buf *b, char c);
#ifdef __GNUC__
/* GCC checks every caller's format string against its arguments. */
int  st_buf_printf(st_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#else
int  st_buf_printf(st_buf *b, const char *fmt, ...);
#endif
/* Drop the first n bytes (consumed input). */
void st_buf_consume(st_buf *b, size_t n);
/* NUL-terminated view; the terminator is not counted in len. */
const char *st_buf_cstr(st_buf *b);
int  st_buf_ok(const st_buf *b);

/* Bounded string copies, with strlcpy/strlcat semantics: the result is always
   terminated, and the return is 1 if all of src fitted, 0 if it was truncated. Use
   these, never strcpy/strcat (D8: flawfinder level 4 fails the audit). */
int  st_copy(char *dst, size_t size, const char *src);
int  st_append(char *dst, size_t size, const char *src);

/* Overwrite memory holding a secret. A plain memset before free or return is a dead
   store the optimizer may remove; the volatile pointer stops that. */
void st_zero(void *p, size_t n);

#endif
