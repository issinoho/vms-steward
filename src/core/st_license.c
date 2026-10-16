/* st_license.c - the licence listings' parser (st_license.h). */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "st_license.h"

void st_license_init(st_license_parser *p, st_license_cb fn, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->part = -1;
    p->fn = fn;
    p->ctx = ctx;
}

static int flush(st_license_parser *p)
{
    if (p->have && !p->stopped && p->fn(&p->cur, p->ctx)) p->stopped = 1;
    p->have = 0;
    p->last = NULL;
    return p->stopped;
}

static void start(st_license_parser *p)
{
    memset(&p->cur, 0, sizeof p->cur);
    p->cur.part = p->part;
    p->have = 1;
    p->last = NULL;
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

/* A continuation: ", " and s[0, n) after what out holds, as far as it fits. */
static void append(char *out, size_t outlen, const char *s, size_t n)
{
    size_t o = strlen(out);
    if (o && o + 2 < outlen) { out[o++] = ','; out[o++] = ' '; out[o] = '\0'; }
    if (o + 1 < outlen) put(out + o, outlen - o, s, n);
}

typedef struct { int part; const char *label; size_t off, size; } field_map;
#define F(part, label, m) { part, label, offsetof(st_license, m), sizeof ((st_license *) 0)->m }
static const field_map fields[] = {
    F(ST_LIC_LOADED,   "Producer",             producer),
    F(ST_LIC_LOADED,   "Units",                units),
    F(ST_LIC_LOADED,   "Version",              version),
    F(ST_LIC_LOADED,   "Release Date",         release),
    F(ST_LIC_LOADED,   "Termination Date",     termination),
    F(ST_LIC_LOADED,   "Availability",         availability),
    F(ST_LIC_LOADED,   "Activity",             activity),
    F(ST_LIC_DATABASE, "Issuer",               issuer),
    F(ST_LIC_DATABASE, "Authorization",        authorization),
    F(ST_LIC_DATABASE, "Product Name",         product),
    F(ST_LIC_DATABASE, "Producer",             producer),
    F(ST_LIC_DATABASE, "Units",                units),
    F(ST_LIC_DATABASE, "Version",              version),
    F(ST_LIC_DATABASE, "Release Date",         release),
    F(ST_LIC_DATABASE, "PAK Termination Date", termination),
    F(ST_LIC_DATABASE, "Availability",         availability),
    F(ST_LIC_DATABASE, "Activity",             activity),
    F(ST_LIC_DATABASE, "Options",              options),
    F(ST_LIC_DATABASE, "Hardware ID",          hardware_id),
    F(ST_LIC_DATABASE, "Revision Level",       revision),
    F(ST_LIC_DATABASE, "Status",               status),
    F(ST_LIC_DATABASE, "Command",              command),
    F(ST_LIC_DATABASE, "Modified by user",     modified_by),
    F(ST_LIC_DATABASE, "Modified on",          modified_on),
};
#undef F

/* "Label: value" (from s[0, n), the label up to the first colon) into the licence:
   its own field, or other[]. Remembers the field for a continuation line. */
static void field(st_license_parser *p, const char *s, size_t n)
{
    const char *colon = memchr(s, ':', n);
    size_t ln = (size_t) (colon - s), i;
    char label[32];
    put(label, sizeof label, s, ln);
    for (i = 0; i < sizeof fields / sizeof fields[0]; i++)
        if (fields[i].part == p->part && !strcmp(fields[i].label, label)) {
            p->last = (char *) &p->cur + fields[i].off;
            p->lastlen = fields[i].size;
            put(p->last, p->lastlen, colon + 1, n - ln - 1);
            return;
        }
    if (p->cur.nother >= ST_LIC_OTHER) { p->last = NULL; return; }
    i = (size_t) p->cur.nother++;
    memcpy(p->cur.other_label[i], label, sizeof label);
    p->last = p->cur.other_value[i];
    p->lastlen = sizeof p->cur.other_value[i];
    put(p->last, p->lastlen, colon + 1, n - ln - 1);
}

/* "Active licenses on node X86VMS:" */
static const char node_prefix[] = "Active licenses on node ";

static int is_product(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (!((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-' || s[i] == '_' ||
              s[i] == '$' || s[i] == '.'))
            return 0;
    return n > 0;
}

static void loaded_line(st_license_parser *p, const char *s, size_t n)
{
    size_t pl = sizeof node_prefix - 1;
    if (*s == '\t' || *s == ' ') {   /* a field of the licence above */
        while (n && (*s == '\t' || *s == ' ')) { s++; n--; }
        if (!p->have || !n) return;
        if (memchr(s, ':', n)) field(p, s, n);
        else if (n == 16 && !memcmp(s, "Per Core License", 16)) p->cur.per_core = 1;
        else append(p->cur.options, sizeof p->cur.options, s, n);
        return;
    }
    if (n > pl && !memcmp(s, node_prefix, pl)) {
        put(p->node, sizeof p->node, s + pl, n - pl - (s[n - 1] == ':'));
        return;
    }
    if (!is_product(s, n)) return;   /* a message, or anything else */
    if (flush(p)) return;
    start(p);
    put(p->cur.product, sizeof p->cur.product, s, n);
}

/* "Type: PCL,   Units Required: 2  (X86_64 Per Core)": the type and the units. */
static void charge_line(st_license_parser *p, const char *s, size_t n)
{
    char line[128];
    const char *t, *e;
    put(line, sizeof line, s, n);
    if (!line[0] || p->ncharge >= ST_LIC_CHARGE_LINES) return;
    memcpy(p->charge[p->ncharge++], line, sizeof line);
    if (!strncmp(line, "Type:", 5)) {
        t = line + 5;
        e = strchr(t, ',');
        put(p->charge_type, sizeof p->charge_type, t, e ? (size_t) (e - t) : strlen(t));
    }
    if ((t = strstr(line, "Units Required:")) != NULL) {
        t += 15;
        while (*t == ' ') t++;
        for (e = t; *e && *e != ' '; e++) {}
        put(p->charge_units, sizeof p->charge_units, t, (size_t) (e - t));
    }
}

/* The database's header, before the first PAK. */
static void db_header(st_license_parser *p, const char *s, size_t n)
{
    static const struct { const char *label; size_t off, size; } h[] = {
        { "License Database File",  offsetof(st_license_parser, db_file),       sizeof ((st_license_parser *) 0)->db_file },
        { "Created on",             offsetof(st_license_parser, db_created),    sizeof ((st_license_parser *) 0)->db_created },
        { "Created by user",        offsetof(st_license_parser, db_created_by), sizeof ((st_license_parser *) 0)->db_created_by },
        { "Created by LMF Version", offsetof(st_license_parser, db_version),    sizeof ((st_license_parser *) 0)->db_version },
    };
    const char *colon = memchr(s, ':', n);
    char label[32];
    size_t i, ln;
    if (!colon) return;
    ln = (size_t) (colon - s);
    put(label, sizeof label, s, ln);
    for (i = 0; i < sizeof h / sizeof h[0]; i++)
        if (!strcmp(h[i].label, label)) put((char *) p + h[i].off, h[i].size, colon + 1, n - ln - 1);
}

static void database_line(st_license_parser *p, const char *s, size_t n)
{
    if (n >= 5 && !memcmp(s, "-----", 5)) {   /* a PAK starts */
        if (flush(p)) return;
        start(p);
        return;
    }
    if (n == 13 && !memcmp(s, "[End Of List]", 13)) { flush(p); return; }
    if (*s == ' ' || *s == '\t') {   /* continues the field above */
        while (n && (*s == '\t' || *s == ' ')) { s++; n--; }
        if (p->have && p->last && n) append(p->last, p->lastlen, s, n);
        return;
    }
    if (!memchr(s, ':', n)) return;
    if (p->have) field(p, s, n);
    else db_header(p, s, n);
}

static const char *const part_names[ST_LIC_PARTS] = { "LOADED", "CHARGE", "DATABASE" };

int st_license_line(st_license_parser *p, const char *line, size_t len)
{
    int i;
    if (p->stopped) return 1;
    while (len && (line[len - 1] == '\r' || line[len - 1] == ' ' || line[len - 1] == '\t')) len--;
    if (!len) return 0;
    if (len > 9 && !memcmp(line, "%%PART%% ", 9)) {
        flush(p);
        p->part = -1;
        for (i = 0; i < ST_LIC_PARTS; i++)
            if (len - 9 == strlen(part_names[i]) && !memcmp(line + 9, part_names[i], len - 9)) p->part = i;
        return p->stopped;
    }
    if (len > 11 && !memcmp(line, "%%STATUS%% ", 11)) {
        char hex[9];
        flush(p);
        if (p->part >= 0 && len - 11 <= 8) {
            memcpy(hex, line + 11, len - 11);
            hex[len - 11] = '\0';
            /* Without DCL's "message already shown" bit, as for %%END%%. */
            p->status[p->part] = (unsigned int) strtoul(hex, NULL, 16) & 0x0FFFFFFFu;
            p->seen[p->part] = 1;
        }
        p->part = -1;
        return p->stopped;
    }
    switch (p->part) {
    case ST_LIC_LOADED:   loaded_line(p, line, len); break;
    case ST_LIC_CHARGE:   charge_line(p, line, len); break;
    case ST_LIC_DATABASE: database_line(p, line, len); break;
    default: break;   /* outside a part: nothing of ours */
    }
    return p->stopped;
}

int st_license_end(st_license_parser *p)
{
    return flush(p);
}

int st_license_ok(const st_license_parser *p, int part)
{
    return part >= 0 && part < ST_LIC_PARTS && p->seen[part] && (p->status[part] & 1);
}
