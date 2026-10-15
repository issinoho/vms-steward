/* st_sysgen.c - the SYSGEN SHOW/ALL parser (st_sysgen.h). */
#include <string.h>
#include "st_sysgen.h"

void st_sysgen_init(st_sysgen_parser *p, st_param_cb fn, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->fn = fn;
    p->ctx = ctx;
}

static int flush(st_sysgen_parser *p)
{
    if (p->have && !p->stopped && p->fn(&p->cur, p->ctx)) p->stopped = 1;
    p->have = 0;
    return p->stopped;
}

/* line[from, to), clamped to len, without blanks either side, into out. A string value
   loses its quotes (and the blanks inside them at the end). Returns 1 if quoted. */
static int field(const char *line, size_t len, size_t from, size_t to, char *out, size_t outlen)
{
    size_t n;
    int quoted = 0;
    out[0] = '\0';
    if (from >= len) return 0;
    if (to > len) to = len;
    while (from < to && (line[from] == ' ' || line[from] == '\t')) from++;
    while (to > from && (line[to - 1] == ' ' || line[to - 1] == '\t')) to--;
    if (to - from >= 2 && line[from] == '"' && line[to - 1] == '"') {
        quoted = 1;
        from++;
        to--;
        while (to > from && line[to - 1] == ' ') to--;
    }
    n = to - from;
    if (n >= outlen) n = outlen - 1;
    memcpy(out, line + from, n);
    out[n] = '\0';
    return quoted;
}

static void values(const char *line, size_t len, size_t from, st_param_values *v)
{
    /* A quoted current value ends one column later than a number (34, not 33). */
    if (from > 34) from = 34;
    field(line, len, from, 34, v->current, sizeof v->current);
    field(line, len, 34, 44, v->dflt, sizeof v->dflt);
    field(line, len, 44, 54, v->min, sizeof v->min);
    field(line, len, 54, 65, v->max, sizeof v->max);
    field(line, len, 66, 76, v->unit, sizeof v->unit);
}

int st_sysgen_line(st_sysgen_parser *p, const char *line, size_t len)
{
    size_t n = 0;
    if (p->stopped) return 1;
    while (len && (line[len - 1] == '\r' || line[len - 1] == ' ')) len--;
    if (!len) return 0;
    if (len > 15 && !strncmp(line, " internal value", 15)) {
        if (p->have) {
            p->cur.has_internal = 1;
            values(line, len, 15, &p->cur.internal);
        }
        return 0;
    }
    /* A parameter's line starts with its name: A-Z, 0-9, _ and $; anything else (the
       headings, the rules, SYSGEN's messages) is not one. */
    while (n < len && n < sizeof p->cur.name &&
           ((line[n] >= 'A' && line[n] <= 'Z') || (line[n] >= '0' && line[n] <= '9') || line[n] == '_' || line[n] == '$'))
        n++;
    if (!n || n >= sizeof p->cur.name || n >= len || line[n] != ' ' ||
        !strncmp(line, "Parameter", 9) || !strncmp(line, "Parameters", 10))
        return 0;
    if (flush(p)) return 1;
    memset(&p->cur, 0, sizeof p->cur);
    memcpy(p->cur.name, line, n);
    p->cur.name[n] = '\0';
    values(line, len, n, &p->cur.v);
    p->cur.ascii = p->cur.v.unit[0] == 'A' && !strcmp(p->cur.v.unit, "Ascii");
    p->cur.dynamic = len > 77 && line[77] == 'D';
    p->have = 1;
    return 0;
}

int st_sysgen_end(st_sysgen_parser *p)
{
    return flush(p);
}
