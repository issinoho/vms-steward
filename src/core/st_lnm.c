/* st_lnm.c - logical names: input rules and the SHOW LOGICAL/FULL parser (st_lnm.h). */
#include <string.h>
#include "st_lnm.h"
#include "st_buf.h"
#include "st_json.h"

static char up(char c) { return (c >= 'a' && c <= 'z') ? (char) (c - 'a' + 'A') : c; }

int st_valid_lnm_table(const char *in, char out[ST_LNM_TABLE_MAX + 1])
{
    /* The process's own tables, and the names that search them. Under a persona these
       are the service's, whose settings (the gateway secret among them) are process
       logical names: never the viewer's to read. */
    static const char *const own[] = {
        "LNM$PROCESS", "LNM$PROCESS_TABLE", "LNM$PROCESS_DIRECTORY", "LNM$JOB",
        "LNM$FILE_DEV", "LNM$DCL_LOGICAL", "LNM$DIRECTORIES", "LNM$TEMPORARY_MAILBOX",
        "LNM$PERMANENT_MAILBOX",
    };
    size_t i, n = strlen(in);
    if (n < 1 || n > ST_LNM_TABLE_MAX) return 0;
    for (i = 0; i < n; i++) {
        char c = up(in[i]);
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '$' || c == '_')) return 0;
        out[i] = c;
    }
    out[n] = '\0';
    for (i = 0; i < sizeof own / sizeof own[0]; i++)
        if (!strcmp(out, own[i])) return 0;
    /* A job table by its own name (LNM$JOB_<address>): one of them is the service's
       job's, and nothing tells a viewer's job from the service's. */
    if (!strncmp(out, "LNM$JOB_", 8)) return 0;
    return 1;
}

int st_valid_lnm_pattern(const char *in, char out[ST_LNM_PATTERN_MAX + 1])
{
    size_t i, n = strlen(in);
    if (n < 1 || n > ST_LNM_PATTERN_MAX) return 0;
    for (i = 0; i < n; i++) {
        char c = up(in[i]);
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '$' || c == '_' || c == '*' || c == '%'))
            return 0;
        out[i] = c;
    }
    out[n] = '\0';
    return 1;
}

int st_valid_lnm_name(const char *in)
{
    size_t i, n = strlen(in);
    if (n < 1 || n > ST_LNM_NAME_MAX) return 0;
    for (i = 0; i < n; i++)
        if ((unsigned char) in[i] < 0x20 || (unsigned char) in[i] > 0x7E) return 0;
    return 1;
}

/* ---- changes (D15) ---- */

static int eq_nocase(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (up(*a) != up(*b)) return 0;
    return *a == *b;
}

int st_lnm_mode(const char *s)
{
    if (eq_nocase(s, "user")) return ST_LNM_USER;
    if (eq_nocase(s, "super") || eq_nocase(s, "supervisor")) return ST_LNM_SUPER;
    if (eq_nocase(s, "exec") || eq_nocase(s, "executive")) return ST_LNM_EXEC;
    return -1;
}

const char *st_lnm_mode_name(int mode)
{
    static const char *const names[] = { "kernel", "exec", "super", "user" };
    return mode >= 0 && mode <= 3 ? names[mode] : "?";
}

/* A string member: 1 to 255 printable ASCII characters, as st_valid_lnm_name. */
static int text(const st_jval *v, char out[ST_LNM_NAME_MAX + 1])
{
    if (!v || v->type != ST_JSTR || v->slen > ST_LNM_NAME_MAX || strlen(v->str) != v->slen) return 0;
    if (!st_valid_lnm_name(v->str)) return 0;
    memcpy(out, v->str, v->slen + 1);
    return 1;
}

/* A list of attribute names into a mask: a and b are the names of bits 1 and 2. */
static int attr_names(const st_jval *v, const char *a, const char *b, unsigned *out)
{
    const st_jval *x;
    *out = 0;
    if (v->type != ST_JARR) return 0;
    for (x = v->child; x; x = x->next) {
        if (x->type != ST_JSTR) return 0;
        if (eq_nocase(x->str, a)) *out |= 1u;
        else if (eq_nocase(x->str, b)) *out |= 2u;
        else return 0;
    }
    return 1;
}

int st_lnm_def_parse(const st_jval *root, st_lnm_def *d, const char **why)
{
    const st_jval *m, *x, *y;
    int have_eq = 0;
    memset(d, 0, sizeof *d);
    d->mode = -1;
    if (!root || root->type != ST_JOBJ) { *why = "The body must be a JSON object"; return -1; }
    for (m = root->child; m; m = m->next) {
        if (!strcmp(m->key, "table")) {
            if (m->type != ST_JSTR || !st_valid_lnm_table(m->str, d->table)) {
                *why = "table: a shareable table, A-Z 0-9 $ _; process and job tables are refused";
                return -1;
            }
        } else if (!strcmp(m->key, "name")) {
            if (!text(m, d->name)) { *why = "name: 1 to 255 printable characters"; return -1; }
        } else if (!strcmp(m->key, "mode")) {
            if (m->type != ST_JSTR || (d->mode = st_lnm_mode(m->str)) < 0) {
                *why = "mode: user, super or exec";
                return -1;
            }
        } else if (!strcmp(m->key, "attributes")) {
            if (!attr_names(m, "confine", "no_alias", &d->attrs)) {
                *why = "attributes: a list of confine and no_alias";
                return -1;
            }
        } else if (!strcmp(m->key, "replace")) {
            if (m->type != ST_JBOOL) { *why = "replace: true or false"; return -1; }
            d->replace = m->boolean != 0;
        } else if (!strcmp(m->key, "equivalences")) {
            if (m->type != ST_JARR || !m->child) { *why = "equivalences: a list of 1 to 16"; return -1; }
            have_eq = 1;
            for (x = m->child; x; x = x->next) {
                st_lnm_defeq *q;
                if (d->neq >= ST_LNM_MAXEQ) { *why = "equivalences: a list of 1 to 16"; return -1; }
                q = &d->eq[d->neq++];
                if (x->type != ST_JOBJ) { *why = "equivalences: each {\"value\", \"attributes\"}"; return -1; }
                for (y = x->child; y; y = y->next) {
                    if (!strcmp(y->key, "value")) {
                        if (!text(y, q->value)) { *why = "equivalences: each value 1 to 255 printable characters"; return -1; }
                    } else if (!strcmp(y->key, "attributes")) {
                        if (!attr_names(y, "concealed", "terminal", &q->attrs)) {
                            *why = "equivalences: attributes a list of concealed and terminal";
                            return -1;
                        }
                    } else { *why = "equivalences: only value and attributes"; return -1; }
                }
                if (!q->value[0]) { *why = "equivalences: each needs a value"; return -1; }
            }
        } else {
            *why = "only table, name, mode, attributes, equivalences and replace";
            return -1;
        }
    }
    if (!d->table[0] || !d->name[0] || d->mode < 0 || !have_eq) {
        *why = "table, name, mode and equivalences are required";
        return -1;
    }
    return 0;
}

/* ---- the parser ---- */

void st_lnm_parse_init(st_lnm_parser *p, st_lnm_cb fn, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->fn = fn;
    p->ctx = ctx;
}

static int flush(st_lnm_parser *p)
{
    if (p->have && !p->stopped) {
        p->have = 0;
        if (p->fn(&p->table, &p->cur, p->ctx)) p->stopped = 1;
    }
    p->have = 0;
    return p->stopped;
}

/* A quoted string at s[*i] ("" is a quote), into out; *i moves past it. 0 if malformed. */
static int quoted(const char *s, size_t len, size_t *i, char *out, size_t outlen)
{
    size_t o = 0;
    if (*i >= len || s[*i] != '"') return 0;
    for ((*i)++; *i < len; (*i)++) {
        if (s[*i] == '"') {
            if (*i + 1 < len && s[*i + 1] == '"') { (*i)++; }
            else { (*i)++; out[o < outlen ? o : outlen - 1] = '\0'; return 1; }
        }
        if (o + 1 < outlen) out[o++] = s[*i];
    }
    return 0;   /* no closing quote */
}

/* A bracketed list at s[*i], "[a,b]", into out without the brackets. */
static int bracket(const char *s, size_t len, size_t *i, char *out, size_t outlen)
{
    size_t o = 0;
    if (*i >= len || s[*i] != '[') return 0;
    for ((*i)++; *i < len && s[*i] != ']'; (*i)++)
        if (o + 1 < outlen) out[o++] = s[*i];
    if (*i >= len) return 0;
    (*i)++;
    out[o] = '\0';
    return 1;
}

static void blanks(const char *s, size_t len, size_t *i)
{
    while (*i < len && (s[*i] == ' ' || s[*i] == '\t')) (*i)++;
}

/* "= "value" [attrs]" at s[*i]: one more equivalence of the current name. */
static void equivalence(st_lnm_parser *p, const char *s, size_t len, size_t i)
{
    st_lnm_eq *e;
    blanks(s, len, &i);
    if (i >= len || s[i] != '=') return;
    i++;
    blanks(s, len, &i);
    if (p->cur.neq == ST_LNM_MAXEQ) { p->cur.more++; return; }
    e = &p->cur.eq[p->cur.neq];
    memset(e, 0, sizeof *e);
    if (!quoted(s, len, &i, e->value, sizeof e->value)) return;
    blanks(s, len, &i);
    if (i < len && s[i] == '[') bracket(s, len, &i, e->attributes, sizeof e->attributes);
    p->cur.neq++;
}

/* "[mode,attr,...]": the first word is the access mode, the rest the attributes. */
static void mode_attrs(const char *list, char *mode, size_t mlen, char *attrs, size_t alen)
{
    const char *comma = strchr(list, ',');
    size_t n = comma ? (size_t) (comma - list) : strlen(list);
    if (n >= mlen) n = mlen - 1;
    memcpy(mode, list, n);
    mode[n] = '\0';
    st_copy(attrs, alen, comma ? comma + 1 : "");
}

int st_lnm_parse_line(st_lnm_parser *p, const char *s, size_t len)
{
    size_t i = 0;
    if (p->stopped) return 1;
    while (len && (s[len - 1] == '\r' || s[len - 1] == '\n')) len--;
    blanks(s, len, &i);
    if (i == len) return 0;

    if (s[i] == '(' && i == 0) {                          /* a table header */
        size_t j = 1, o = 0;
        char list[96];
        if (flush(p)) return 1;
        memset(&p->table, 0, sizeof p->table);
        while (j < len && s[j] != ')' && o < ST_LNM_TABLE_MAX) p->table.name[o++] = s[j++];
        p->table.name[o] = '\0';
        while (j < len && s[j] != ')') j++;
        if (j < len) j++;
        blanks(s, len, &j);
        if (bracket(s, len, &j, list, sizeof list)) {
            st_copy(p->table.mode, sizeof p->table.mode, list);
            blanks(s, len, &j);
            if (bracket(s, len, &j, list, sizeof list)) st_copy(p->table.attributes, sizeof p->table.attributes, list);
        }
        p->tables++;
        return 0;
    }
    if (s[i] == '[' && len - i >= 12 && !memcmp(s + i, "[Protection=", 12)) {   /* the header's second line */
        size_t j = i + 12, o = 0;
        while (j < len && s[j] != ']' && o + 1 < sizeof p->table.protection) p->table.protection[o++] = s[j++];
        p->table.protection[o] = '\0';
        if (j < len) j++;
        blanks(s, len, &j);
        if (j + 7 < len && !memcmp(s + j, "[Owner=", 7)) {
            /* The owner is a UIC, itself bracketed ([Owner=[SYSTEM]]), kept with its
               brackets; or a bare word, up to the closing bracket. */
            int uic;
            j += 7;
            uic = j < len && s[j] == '[';
            o = 0;
            while (j < len && o + 1 < sizeof p->table.owner) {
                if (!uic && s[j] == ']') break;
                p->table.owner[o++] = s[j++];
                if (uic && s[j - 1] == ']') break;
            }
            p->table.owner[o] = '\0';
        }
        return 0;
    }
    if (s[i] == '"') {                                    /* a name */
        char list[96] = "";
        if (flush(p)) return 1;
        memset(&p->cur, 0, sizeof p->cur);
        if (!quoted(s, len, &i, p->cur.name, sizeof p->cur.name)) return 0;
        blanks(s, len, &i);
        if (i < len && s[i] == '[' && bracket(s, len, &i, list, sizeof list))
            mode_attrs(list, p->cur.mode, sizeof p->cur.mode, p->cur.attributes, sizeof p->cur.attributes);
        p->have = 1;
        equivalence(p, s, len, i);
        return 0;
    }
    if (s[i] == '=' && p->have) {                          /* another equivalence */
        equivalence(p, s, len, i);
        return 0;
    }
    if (s[i] == '%' && i == 0) {                           /* a message, e.g. %SYSTEM-F-NOLOGTAB */
        size_t n = len < sizeof p->message - 1 ? len : sizeof p->message - 1;
        memcpy(p->message, s, n);
        p->message[n] = '\0';
    }
    return 0;   /* anything else (iteration lines, blank lines) is not a name */
}

int st_lnm_parse_end(st_lnm_parser *p)
{
    return flush(p);
}
