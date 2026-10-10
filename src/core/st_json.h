/* st_json.h - JSON writer and strict parser (RFC 8259), no I/O.

   Character sets: the browser speaks UTF-8, and OpenVMS strings (owner names, account
   names, identifier names) are ISO-8859-1. The writer takes ISO-8859-1 and emits UTF-8.
   The parser returns UTF-8, and st_json_latin1() converts a value for the platform,
   refusing characters above U+00FF.

   Parser limits: nesting depth ST_JSON_MAX_DEPTH, members/elements per container
   ST_JSON_MAX_ITEMS. Duplicate keys, NUL characters, lone surrogates and invalid
   UTF-8 are errors, not something to resolve quietly. */
#ifndef ST_JSON_H
#define ST_JSON_H

#include <stddef.h>
#include "st_buf.h"

#define ST_JSON_MAX_DEPTH 32
#define ST_JSON_MAX_ITEMS 4096

/* ---- writer ---- */
typedef struct {
    st_buf       *b;
    int           depth;
    int           after_key;
    unsigned char first[ST_JSON_MAX_DEPTH + 1];
} st_jw;

void st_jw_init(st_jw *w, st_buf *b);
void st_jw_obj(st_jw *w);
void st_jw_obj_end(st_jw *w);
void st_jw_arr(st_jw *w);
void st_jw_arr_end(st_jw *w);
void st_jw_key(st_jw *w, const char *key);              /* ASCII keys */
void st_jw_str(st_jw *w, const char *latin1);
void st_jw_strn(st_jw *w, const char *latin1, size_t n);
void st_jw_int(st_jw *w, long long v);
void st_jw_bool(st_jw *w, int v);
void st_jw_null(st_jw *w);
/* key + value shorthands */
void st_jw_kstr(st_jw *w, const char *key, const char *latin1);
void st_jw_kint(st_jw *w, const char *key, long long v);
void st_jw_kbool(st_jw *w, const char *key, int v);

/* ---- parser ---- */
typedef enum { ST_JNULL, ST_JBOOL, ST_JNUM, ST_JSTR, ST_JARR, ST_JOBJ } st_jtype;

typedef struct st_jval {
    st_jtype        type;
    int             boolean;
    double          num;
    const char     *str;    /* UTF-8, NUL-terminated (strings, and keys in .key) */
    size_t          slen;
    const char     *key;    /* set on object members */
    struct st_jval *child;  /* first element/member */
    struct st_jval *next;   /* next sibling */
    size_t          count;
} st_jval;

typedef struct st_jblock st_jblock;

typedef struct {
    st_jval   *root;
    char      *strings;     /* decoded strings, scrubbed on free (may hold passwords) */
    size_t     strings_len;
    st_jblock *blocks;
} st_jdoc;

/* Returns 0, or -1 with a short reason in err. */
int  st_json_parse(st_jdoc *doc, const char *text, size_t len, char *err, size_t errlen);
void st_json_free(st_jdoc *doc);

const st_jval *st_json_get(const st_jval *obj, const char *key);
/* The member's string, or NULL if absent or not a string. */
const char *st_json_get_str(const st_jval *obj, const char *key);
/* 1 if the member is a whole number within [lo, hi], storing it. */
int st_json_get_int(const st_jval *obj, const char *key, long long lo, long long hi,
                    long long *out);

/* UTF-8 to ISO-8859-1 into out[outlen]. Returns 0, or -1 for a character above U+00FF
   or a result that does not fit. */
int st_json_latin1(const char *utf8, size_t len, char *out, size_t outlen);

#endif
