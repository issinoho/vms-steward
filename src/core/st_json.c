/* st_json.c - JSON writer and strict parser, no I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_json.h"

/* ================================ writer ================================ */

void st_jw_init(st_jw *w, st_buf *b)
{
    memset(w, 0, sizeof *w);
    w->b = b;
    w->first[0] = 1;
}

/* Comma before a value or key, unless it directly follows a key. */
static void sep(st_jw *w)
{
    if (w->after_key) { w->after_key = 0; return; }
    if (!w->first[w->depth]) st_buf_putc(w->b, ',');
    w->first[w->depth] = 0;
}

static void open_c(st_jw *w, char c)
{
    sep(w);
    st_buf_putc(w->b, c);
    if (w->depth < ST_JSON_MAX_DEPTH) w->depth++;
    else w->b->overflow = 1;
    w->first[w->depth] = 1;
}

static void close_c(st_jw *w, char c)
{
    if (w->depth > 0) w->depth--;
    st_buf_putc(w->b, c);
}

void st_jw_obj(st_jw *w)     { open_c(w, '{'); }
void st_jw_obj_end(st_jw *w) { close_c(w, '}'); }
void st_jw_arr(st_jw *w)     { open_c(w, '['); }
void st_jw_arr_end(st_jw *w) { close_c(w, ']'); }

/* Escape for JSON, ISO-8859-1 in, UTF-8 out. <, > and & are escaped as well, so a
   response mistakenly rendered as HTML cannot carry markup. */
static void put_str(st_buf *b, const unsigned char *s, size_t n)
{
    size_t i;
    st_buf_putc(b, '"');
    for (i = 0; i < n; i++) {
        unsigned char c = s[i];
        switch (c) {
        case '"':  st_buf_puts(b, "\\\""); break;
        case '\\': st_buf_puts(b, "\\\\"); break;
        case '\n': st_buf_puts(b, "\\n"); break;
        case '\r': st_buf_puts(b, "\\r"); break;
        case '\t': st_buf_puts(b, "\\t"); break;
        case '<': case '>': case '&':
            st_buf_printf(b, "\\u%04x", c); break;
        default:
            if (c < 0x20 || c == 0x7F) st_buf_printf(b, "\\u%04x", c);
            else if (c < 0x80) st_buf_putc(b, (char) c);
            else {
                st_buf_putc(b, (char) (0xC0 | (c >> 6)));
                st_buf_putc(b, (char) (0x80 | (c & 0x3F)));
            }
        }
    }
    st_buf_putc(b, '"');
}

void st_jw_key(st_jw *w, const char *key)
{
    sep(w);
    put_str(w->b, (const unsigned char *) key, strlen(key));
    st_buf_putc(w->b, ':');
    w->after_key = 1;
}

void st_jw_strn(st_jw *w, const char *s, size_t n) { sep(w); put_str(w->b, (const unsigned char *) s, n); }
void st_jw_str(st_jw *w, const char *s) { st_jw_strn(w, s, strlen(s)); }
void st_jw_int(st_jw *w, long long v)   { sep(w); st_buf_printf(w->b, "%lld", v); }
void st_jw_bool(st_jw *w, int v)        { sep(w); st_buf_puts(w->b, v ? "true" : "false"); }
void st_jw_null(st_jw *w)               { sep(w); st_buf_puts(w->b, "null"); }

void st_jw_kstr(st_jw *w, const char *k, const char *s) { st_jw_key(w, k); st_jw_str(w, s); }
void st_jw_kint(st_jw *w, const char *k, long long v)   { st_jw_key(w, k); st_jw_int(w, v); }
void st_jw_kbool(st_jw *w, const char *k, int v)        { st_jw_key(w, k); st_jw_bool(w, v); }

/* ================================ parser ================================ */

#define BLOCK_NODES 128

struct st_jblock {
    st_jblock *next;
    size_t     used;
    st_jval    nodes[BLOCK_NODES];
};

typedef struct {
    const unsigned char *p, *end;
    st_jdoc *doc;
    char    *sp;            /* next free byte in doc->strings */
    const char *err;
} parser;

static st_jval *new_node(parser *ps, st_jtype t)
{
    st_jblock *bl = ps->doc->blocks;
    st_jval *v;
    if (!bl || bl->used == BLOCK_NODES) {
        bl = malloc(sizeof *bl);
        if (!bl) { ps->err = "out of memory"; return NULL; }
        bl->next = ps->doc->blocks;
        bl->used = 0;
        ps->doc->blocks = bl;
    }
    v = &bl->nodes[bl->used++];
    memset(v, 0, sizeof *v);
    v->type = t;
    return v;
}

static void ws(parser *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static int lit(parser *ps, const char *w)
{
    size_t n = strlen(w);
    if ((size_t) (ps->end - ps->p) < n || memcmp(ps->p, w, n)) { ps->err = "invalid literal"; return 0; }
    ps->p += n;
    return 1;
}

static int hex4(const unsigned char *p, unsigned int *out)
{
    unsigned int v = 0; int i;
    for (i = 0; i < 4; i++) {
        unsigned char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return 0;
    }
    *out = v;
    return 1;
}

static void put_utf8(parser *ps, unsigned int cp)
{
    char *s = ps->sp;
    if (cp < 0x80) *s++ = (char) cp;
    else if (cp < 0x800) { *s++ = (char) (0xC0 | (cp >> 6)); *s++ = (char) (0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
        *s++ = (char) (0xE0 | (cp >> 12)); *s++ = (char) (0x80 | ((cp >> 6) & 0x3F));
        *s++ = (char) (0x80 | (cp & 0x3F));
    } else {
        *s++ = (char) (0xF0 | (cp >> 18)); *s++ = (char) (0x80 | ((cp >> 12) & 0x3F));
        *s++ = (char) (0x80 | ((cp >> 6) & 0x3F)); *s++ = (char) (0x80 | (cp & 0x3F));
    }
    ps->sp = s;
}

/* Length of a valid UTF-8 sequence at p (1-4), or 0. Rejects overlongs and
   surrogates. */
static int utf8_len(const unsigned char *p, const unsigned char *end)
{
    unsigned char c = p[0];
    int n, i; unsigned int cp;
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) { n = 2; cp = c & 0x1F; }
    else if (c >= 0xE0 && c <= 0xEF) { n = 3; cp = c & 0x0F; }
    else if (c >= 0xF0 && c <= 0xF4) { n = 4; cp = c & 0x07; }
    else return 0;
    if (end - p < n) return 0;
    for (i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (p[i] & 0x3F);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))) return 0;
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    return n;
}

/* Decodes into the string pool. Every decoded string, with its terminator, fits in
   the source bytes it came from (quotes included), so the pool never overflows. */
static const char *string(parser *ps, size_t *len)
{
    char *start = ps->sp;
    ps->p++;   /* opening quote */
    for (;;) {
        unsigned char c;
        if (ps->p >= ps->end) { ps->err = "unterminated string"; return NULL; }
        c = *ps->p;
        if (c == '"') { ps->p++; break; }
        if (c < 0x20) { ps->err = "control character in string"; return NULL; }
        if (c == '\\') {
            if (ps->end - ps->p < 2) { ps->err = "bad escape"; return NULL; }
            c = ps->p[1];
            ps->p += 2;
            switch (c) {
            case '"': *ps->sp++ = '"'; break;
            case '\\': *ps->sp++ = '\\'; break;
            case '/': *ps->sp++ = '/'; break;
            case 'b': *ps->sp++ = '\b'; break;
            case 'f': *ps->sp++ = '\f'; break;
            case 'n': *ps->sp++ = '\n'; break;
            case 'r': *ps->sp++ = '\r'; break;
            case 't': *ps->sp++ = '\t'; break;
            case 'u': {
                unsigned int cp, lo;
                if (ps->end - ps->p < 4 || !hex4(ps->p, &cp)) { ps->err = "bad \\u escape"; return NULL; }
                ps->p += 4;
                if (cp >= 0xDC00 && cp <= 0xDFFF) { ps->err = "lone surrogate"; return NULL; }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (ps->end - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u' ||
                        !hex4(ps->p + 2, &lo) || lo < 0xDC00 || lo > 0xDFFF) {
                        ps->err = "lone surrogate"; return NULL;
                    }
                    ps->p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (cp == 0) { ps->err = "NUL in string"; return NULL; }
                put_utf8(ps, cp);
                break;
            }
            default: ps->err = "bad escape"; return NULL;
            }
        } else {
            int n = utf8_len(ps->p, ps->end);
            if (!n) { ps->err = "invalid UTF-8"; return NULL; }
            memcpy(ps->sp, ps->p, (size_t) n);
            ps->sp += n;
            ps->p += n;
        }
    }
    *ps->sp++ = '\0';
    *len = (size_t) (ps->sp - start - 1);
    return start;
}

static int number(parser *ps, st_jval *v)
{
    const unsigned char *s = ps->p;
    char tmp[64];
    size_t n;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end) goto bad;
    if (*ps->p == '0') ps->p++;
    else if (*ps->p >= '1' && *ps->p <= '9') while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    else goto bad;
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') goto bad;
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') goto bad;
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    n = (size_t) (ps->p - s);
    if (n >= sizeof tmp) { ps->err = "number too long"; return 0; }
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    v->num = strtod(tmp, NULL);
    return 1;
bad:
    ps->err = "invalid number";
    return 0;
}

static st_jval *value(parser *ps, int depth);

static st_jval *container(parser *ps, int depth, int is_obj)
{
    st_jval *v = new_node(ps, is_obj ? ST_JOBJ : ST_JARR), *last = NULL;
    char close = is_obj ? '}' : ']';
    if (!v) return NULL;
    if (depth >= ST_JSON_MAX_DEPTH) { ps->err = "nested too deeply"; return NULL; }
    ps->p++;
    ws(ps);
    if (ps->p < ps->end && *ps->p == close) { ps->p++; return v; }
    for (;;) {
        const char *key = NULL;
        size_t klen;
        st_jval *item;
        if (is_obj) {
            const st_jval *m;
            if (ps->p >= ps->end || *ps->p != '"') { ps->err = "expected key"; return NULL; }
            if (!(key = string(ps, &klen))) return NULL;
            for (m = v->child; m; m = m->next)
                if (!strcmp(m->key, key)) { ps->err = "duplicate key"; return NULL; }
            ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') { ps->err = "expected ':'"; return NULL; }
            ps->p++;
        }
        if (!(item = value(ps, depth + 1))) return NULL;
        item->key = key;
        if (last) last->next = item; else v->child = item;
        last = item;
        if (++v->count > ST_JSON_MAX_ITEMS) { ps->err = "too many items"; return NULL; }
        ws(ps);
        if (ps->p < ps->end && *ps->p == ',') { ps->p++; ws(ps); continue; }
        if (ps->p < ps->end && *ps->p == close) { ps->p++; return v; }
        ps->err = is_obj ? "expected ',' or '}'" : "expected ',' or ']'";
        return NULL;
    }
}

static st_jval *value(parser *ps, int depth)
{
    st_jval *v;
    ws(ps);
    if (ps->p >= ps->end) { ps->err = "unexpected end"; return NULL; }
    switch (*ps->p) {
    case '{': return container(ps, depth, 1);
    case '[': return container(ps, depth, 0);
    case '"':
        if (!(v = new_node(ps, ST_JSTR))) return NULL;
        return (v->str = string(ps, &v->slen)) ? v : NULL;
    case 't': if (!lit(ps, "true")) return NULL;
              if ((v = new_node(ps, ST_JBOOL))) v->boolean = 1;
              return v;
    case 'f': if (!lit(ps, "false")) return NULL;
              return new_node(ps, ST_JBOOL);
    case 'n': if (!lit(ps, "null")) return NULL;
              return new_node(ps, ST_JNULL);
    default:
        if (!(v = new_node(ps, ST_JNUM))) return NULL;
        return number(ps, v) ? v : NULL;
    }
}

int st_json_parse(st_jdoc *doc, const char *text, size_t len, char *err, size_t errlen)
{
    parser ps;
    memset(doc, 0, sizeof *doc);
    doc->strings = malloc(len + 1);
    if (!doc->strings) { if (errlen) snprintf(err, errlen, "out of memory"); return -1; }
    doc->strings_len = len + 1;
    ps.p = (const unsigned char *) text;
    ps.end = ps.p + len;
    ps.doc = doc;
    ps.sp = doc->strings;
    ps.err = NULL;
    doc->root = value(&ps, 0);
    if (doc->root) {
        ws(&ps);
        if (ps.p != ps.end) { ps.err = "trailing characters"; doc->root = NULL; }
    }
    if (!doc->root) {
        if (errlen) snprintf(err, errlen, "%s at byte %lu", ps.err ? ps.err : "error",
                             (unsigned long) (ps.p - (const unsigned char *) text));
        st_json_free(doc);
        return -1;
    }
    return 0;
}

void st_json_free(st_jdoc *doc)
{
    while (doc->blocks) {
        st_jblock *n = doc->blocks->next;
        free(doc->blocks);
        doc->blocks = n;
    }
    if (doc->strings) {
        st_zero(doc->strings, doc->strings_len);
        free(doc->strings);
    }
    memset(doc, 0, sizeof *doc);
}

const st_jval *st_json_get(const st_jval *obj, const char *key)
{
    const st_jval *m;
    if (!obj || obj->type != ST_JOBJ) return NULL;
    for (m = obj->child; m; m = m->next)
        if (!strcmp(m->key, key)) return m;
    return NULL;
}

const char *st_json_get_str(const st_jval *obj, const char *key)
{
    const st_jval *v = st_json_get(obj, key);
    return v && v->type == ST_JSTR ? v->str : NULL;
}

int st_json_get_int(const st_jval *obj, const char *key, long long lo, long long hi,
                    long long *out)
{
    const st_jval *v = st_json_get(obj, key);
    long long i;
    if (!v || v->type != ST_JNUM) return 0;
    if (v->num < (double) lo || v->num > (double) hi) return 0;
    i = (long long) v->num;
    if ((double) i != v->num) return 0;
    *out = i;
    return 1;
}

int st_json_latin1(const char *utf8, size_t len, char *out, size_t outlen)
{
    const unsigned char *p = (const unsigned char *) utf8, *end = p + len;
    size_t o = 0;
    while (p < end) {
        unsigned int cp;
        if (*p < 0x80) cp = *p++;
        else if ((*p == 0xC2 || *p == 0xC3) && end - p >= 2 && (p[1] & 0xC0) == 0x80) {
            cp = ((unsigned int) (p[0] & 0x1F) << 6) | (p[1] & 0x3F);
            p += 2;
        } else return -1;
        if (o + 1 >= outlen) return -1;
        out[o++] = (char) cp;
    }
    if (o >= outlen) return -1;
    out[o] = '\0';
    return 0;
}
