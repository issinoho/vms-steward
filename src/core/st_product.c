/* st_product.c - the installed-products parsers (st_product.h). */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "st_product.h"

void st_product_init(st_product_parser *p, st_product_cb fn, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->part = -1;
    p->fn = fn;
    p->ctx = ctx;
}

static int flush(st_product_parser *p)
{
    if (p->have && !p->stopped && p->fn(&p->cur, p->ctx)) p->stopped = 1;
    p->have = 0;
    return p->stopped;
}

/* s[0, n) without blanks either side, into out (cut to fit). */
static void put(char *out, size_t outlen, const char *s, size_t n)
{
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    if (n >= outlen) n = outlen - 1;
    memcpy(out, s, n);
    out[n] = '\0';
}

/* ", " and s[0, n) after what out holds, as far as it fits; nothing for blanks. */
static void append(char *out, size_t outlen, const char *s, size_t n)
{
    size_t o = strlen(out);
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    if (!n) return;
    if (o && o + 2 < outlen) { out[o++] = ','; out[o++] = ' '; out[o] = '\0'; }
    if (o + 1 < outlen) put(out + o, outlen - o, s, n);
}

/* The columns by their heading. list: an indented line adds to it. */
enum { C_PRODUCT = 0 };
typedef struct { const char *heading; size_t off, size; int list; } column_map;
#define C(h, m, l) { h, offsetof(st_product, m), sizeof ((st_product *) 0)->m, l }
static const column_map columns[] = {
    { "PRODUCT", 0, 0, 0 },          /* C_PRODUCT: split into its four words */
    C("KIT TYPE",      kit_type,      0),
    C("KIT FORMAT",    kit_format,    0),
    C("STATE",         state,         0),
    C("MAINTENANCE",   maintenance,   1),
    C("REFERENCED BY", referenced_by, 1),
    C("OPERATION",     operation,     0),
    C("VAL",           validation,    0),
    C("DATE AND TIME", date,          0),
    C("ERR",           error,         0),
    C("USER NAME",     user,          0),
    C("REMARK",        remark,        1),
};
#undef C
#define NCOLUMNS ((int) (sizeof columns / sizeof columns[0]))

static int is_rule(const char *s, size_t n)
{
    size_t i;
    if (!n || s[0] != '-') return 0;
    for (i = 0; i < n; i++) if (s[i] != '-' && s[i] != ' ') return 0;
    return 1;
}

/* The rule above the heading: each run of dashes is a column. */
static void take_rule(st_product_parser *p, const char *s, size_t n)
{
    size_t i = 0;
    p->ncol = 0;
    while (i < n && p->ncol < ST_PROD_COLS) {
        size_t a;
        while (i < n && s[i] == ' ') i++;
        if (i >= n) break;
        a = i;
        while (i < n && s[i] == '-') i++;
        p->col_start[p->ncol] = a;
        p->col_width[p->ncol] = i - a;
        p->col_field[p->ncol] = -1;
        p->ncol++;
    }
}

/* The heading: which column is which. */
static void take_heading(st_product_parser *p, const char *s, size_t n)
{
    int c, f;
    for (c = 0; c < p->ncol; c++) {
        char h[32];
        size_t a = p->col_start[c], w = p->col_width[c];
        if (a >= n) break;
        put(h, sizeof h, s + a, (a + w <= n ? w : n - a));
        for (f = 0; f < NCOLUMNS; f++)
            if (!strcmp(h, columns[f].heading)) p->col_field[c] = f;
    }
}

/* Column c of s[0, n), its start moved by shift; the last column runs to the end. */
static void cell(const st_product_parser *p, int c, size_t shift, const char *s, size_t n,
                 const char **out, size_t *outlen)
{
    size_t a = p->col_start[c] + shift, e = c + 1 < p->ncol ? a + p->col_width[c] : n;
    if (a >= n) { *out = s + n; *outlen = 0; return; }
    if (e > n) e = n;
    *out = s + a;
    *outlen = e - a;
}

/* "<producer> <base> <name> <version>": up to four words from the start of s; the
   offset after the last one is returned. */
static size_t product_words(st_product *r, const char *s, size_t n)
{
    char *dest[4];
    size_t sizes[4], i = 0;
    int w;
    dest[0] = r->producer; sizes[0] = sizeof r->producer;
    dest[1] = r->base;     sizes[1] = sizeof r->base;
    dest[2] = r->name;     sizes[2] = sizeof r->name;
    dest[3] = r->version;  sizes[3] = sizeof r->version;
    for (w = 0; w < 4; w++) {
        size_t a;
        while (i < n && s[i] == ' ') i++;
        if (i >= n) break;
        a = i;
        while (i < n && s[i] != ' ') i++;
        put(dest[w], sizes[w], s + a, i - a);
    }
    return i;
}

static void row(st_product_parser *p, const char *s, size_t n)
{
    size_t shift = 0;
    int c;
    if (flush(p)) return;
    memset(&p->cur, 0, sizeof p->cur);
    p->cur.part = p->part;
    p->have = 1;
    for (c = 0; c < p->ncol; c++)
        if (p->col_field[c] == C_PRODUCT) {
            size_t end = product_words(&p->cur, s, n), lim = p->col_start[c] + p->col_width[c];
            if (end > lim) shift = end - lim;
        }
    for (c = 0; c < p->ncol; c++) {
        const char *v;
        size_t vn;
        int f = p->col_field[c];
        if (f <= C_PRODUCT) continue;
        cell(p, c, shift, s, n, &v, &vn);
        put((char *) &p->cur + columns[f].off, columns[f].size, v, vn);
    }
}

/* An indented line: more of the list columns of the row above. */
static void more(st_product_parser *p, const char *s, size_t n)
{
    int c;
    if (!p->have) return;
    for (c = 0; c < p->ncol; c++) {
        const char *v;
        size_t vn;
        int f = p->col_field[c];
        if (f <= C_PRODUCT || !columns[f].list) continue;
        cell(p, c, 0, s, n, &v, &vn);
        append((char *) &p->cur + columns[f].off, columns[f].size, v, vn);
    }
}

static void table_line(st_product_parser *p, const char *s, size_t n)
{
    if (is_rule(s, n)) {
        if (p->rules == 0) take_rule(p, s, n);
        else if (p->rules == 2) flush(p);   /* the rule under the last row */
        p->rules++;
        return;
    }
    if (p->rules == 1) { take_heading(p, s, n); return; }
    if (p->rules != 2) return;   /* before the table, or the count and legend after */
    if (s[0] == ' ' || s[0] == '\t') more(p, s, n);
    else row(p, s, n);
}

static const char *const part_names[ST_PROD_PARTS] = { "PRODUCTS", "HISTORY", "KITS" };

int st_product_line(st_product_parser *p, const char *line, size_t len)
{
    int i;
    if (p->stopped) return 1;
    while (len && (line[len - 1] == '\r' || line[len - 1] == ' ' || line[len - 1] == '\t')) len--;
    if (!len) return 0;
    if (len > 9 && !memcmp(line, "%%PART%% ", 9)) {
        flush(p);
        p->part = -1;
        p->rules = 0;
        p->ncol = 0;
        for (i = 0; i < ST_PROD_PARTS; i++)
            if (len - 9 == strlen(part_names[i]) && !memcmp(line + 9, part_names[i], len - 9)) p->part = i;
        return p->stopped;
    }
    if (len > 11 && !memcmp(line, "%%STATUS%% ", 11)) {
        char hex[9];
        flush(p);
        if (p->part >= 0 && len - 11 <= 8) {
            memcpy(hex, line + 11, len - 11);
            hex[len - 11] = '\0';
            /* Without DCL's "message already shown" bit, as for licences. */
            p->status[p->part] = (unsigned int) strtoul(hex, NULL, 16) & 0x0FFFFFFFu;
            p->seen[p->part] = 1;
        }
        p->part = -1;
        return p->stopped;
    }
    if (p->part < 0) return p->stopped;
    if (line[0] == '%' && !p->message[p->part][0]) {   /* PRODUCT's message, as it printed it */
        put(p->message[p->part], sizeof p->message[p->part], line, len);
        return p->stopped;
    }
    table_line(p, line, len);
    return p->stopped;
}

int st_product_end(st_product_parser *p)
{
    return flush(p);
}

int st_product_ok(const st_product_parser *p, int part)
{
    return part >= 0 && part < ST_PROD_PARTS && p->seen[part] && (p->status[part] & 1);
}

/* " 5-JUL-2024" or "21-APR-2023": a day of one or two digits, blanks before. */
static int is_date(const char *s)
{
    size_t d = 0;
    while (*s == ' ') s++;
    while (d < 2 && s[d] >= '0' && s[d] <= '9') d++;
    if (!d) return 0;
    s += d;
    return strlen(s) == 9 && s[0] == '-' && s[1] >= 'A' && s[1] <= 'Z' && s[2] >= 'A' && s[2] <= 'Z'
        && s[3] >= 'A' && s[3] <= 'Z' && s[4] == '-' && s[5] >= '0' && s[5] <= '9' && s[6] >= '0' && s[6] <= '9'
        && s[7] >= '0' && s[7] <= '9' && s[8] >= '0' && s[8] <= '9';
}

int st_vmsinstal_line(const char *line, size_t len, st_vmsinstal *v)
{
    char *dest[9];
    size_t sizes[9], a = 0, i;
    int f = 0;
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    memset(v, 0, sizeof *v);
    dest[0] = v->name;      sizes[0] = sizeof v->name;
    dest[1] = v->mnemonic;  sizes[1] = sizeof v->mnemonic;
    dest[2] = v->version;   sizes[2] = sizeof v->version;
    dest[3] = v->date;      sizes[3] = sizeof v->date;
    dest[4] = v->status;    sizes[4] = sizeof v->status;
    dest[5] = v->ivp;       sizes[5] = sizeof v->ivp;
    dest[6] = v->node;      sizes[6] = sizeof v->node;
    dest[7] = v->installer; sizes[7] = sizeof v->installer;
    dest[8] = v->signature; sizes[8] = sizeof v->signature;
    for (i = 0; i <= len; i++)
        if (i == len || line[i] == '|') {
            if (f >= 9) { memset(v, 0, sizeof *v); return 0; }   /* too many fields: not a run */
            put(dest[f], sizes[f], line + a, i - a);
            f++;
            a = i + 1;
        }
    if (f != 9 || !is_date(v->date) || !v->mnemonic[0]) { memset(v, 0, sizeof *v); return 0; }
    return 1;
}

/* ---- installing and removing (12b, D26) ---- */

static int in_set(char c, const char *set) { return c && strchr(set, c) != NULL; }

int st_valid_pcsi_word(const char *s, size_t max)
{
    size_t n = strlen(s), i;
    if (n < 1 || n > max) return 0;
    for (i = 0; i < n; i++)
        if (!in_set(s[i], "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-.")) return 0;
    return 1;
}

int st_valid_kit_dir(const char *s)
{
    size_t n = strlen(s), i;
    int opens = 0, closes = 0;
    if (n < 3 || n > 200 || s[n - 1] != ']' || !strchr(s, '[')) return 0;
    for (i = 0; i < n; i++) {
        if (!in_set(s[i], "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-.:[]")) return 0;
        if (s[i] == '[') opens++;
        if (s[i] == ']') closes++;
    }
    /* "DEV:[A.B]", or rooted "DEV:[A.][B]": no more. */
    return opens == closes && opens <= 2 && !strstr(s, "..");
}

const char *st_product_refused(const char *producer, const char *base, const char *name)
{
    (void) producer;
    (void) base;
    if (!strcmp(name, "STEWARD"))
        return "Steward's own product: installing or removing it would replace or stop the pool serving "
               "this request. Use PRODUCT and STEWARD$CONTROL at a terminal.";
    if (!strcmp(name, "VMS")) return "the operating system";
    return NULL;
}

int st_valid_pcsi_log(const char *s)
{
    size_t i;
    if (strlen(s) != 31 || strncmp(s, "STEWARD_PCSI_", 13) || strcmp(s + 27, ".LOG")) return 0;
    for (i = 13; i < 27; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}
