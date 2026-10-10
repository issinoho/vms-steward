/* st_buf.c - growable byte buffers and secret scrubbing. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_buf.h"

void st_buf_init(st_buf *b, size_t limit)
{
    memset(b, 0, sizeof *b);
    b->limit = limit;
}

void st_buf_free(st_buf *b)
{
    if (b->data) {
        st_zero(b->data, b->cap);   /* buffers may have held passwords or tokens */
        free(b->data);
    }
    st_buf_init(b, b->limit);
}

void st_buf_reset(st_buf *b)
{
    if (b->data) st_zero(b->data, b->len);
    b->len = 0;
    b->overflow = b->oom = 0;
}

static int reserve(st_buf *b, size_t extra)
{
    size_t need, cap;
    char *p;
    if (b->overflow || b->oom) return 0;
    if (extra > (size_t) -1 - b->len - 1) { b->overflow = 1; return 0; }
    need = b->len + extra + 1;
    if (b->limit && need - 1 > b->limit) { b->overflow = 1; return 0; }
    if (need <= b->cap) return 1;
    cap = b->cap ? b->cap : 256;
    while (cap < need) cap = cap > ((size_t) -1) / 2 ? need : cap * 2;
    p = malloc(cap);
    if (!p) { b->oom = 1; return 0; }
    if (b->data) {
        memcpy(p, b->data, b->len);
        st_zero(b->data, b->cap);
        free(b->data);
    }
    b->data = p;
    b->cap = cap;
    return 1;
}

int st_buf_append(st_buf *b, const void *p, size_t n)
{
    if (!reserve(b, n)) return 0;
    if (n) memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 1;
}

int st_buf_puts(st_buf *b, const char *s) { return st_buf_append(b, s, strlen(s)); }

int st_buf_putc(st_buf *b, char c) { return st_buf_append(b, &c, 1); }

int st_buf_printf(st_buf *b, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t) n >= sizeof tmp) { b->overflow = 1; return 0; }
    return st_buf_append(b, tmp, (size_t) n);
}

void st_buf_consume(st_buf *b, size_t n)
{
    if (n >= b->len) { b->len = 0; if (b->data) b->data[0] = '\0'; return; }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
    b->data[b->len] = '\0';
}

const char *st_buf_cstr(st_buf *b)
{
    if (!b->data && !reserve(b, 0)) return "";
    b->data[b->len] = '\0';
    return b->data;
}

int st_buf_ok(const st_buf *b) { return !b->overflow && !b->oom; }

void st_zero(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}
