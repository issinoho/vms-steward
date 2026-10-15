/* svc_logicals.c - logical names, read-only (Phase 7, D14).

   GET api/v1/logicals/tables              the shareable tables, from LNM$SYSTEM_DIRECTORY
   GET api/v1/logicals?table=&filter=      the names in a table, as SHOW LOGICAL/FULL
   GET api/v1/logicals/{table}/{name}      one name and its translation chain

   Listing goes through a short-lived process that is the viewer (D14), so OpenVMS
   decides what is shown. The process and job tables are never offered: under a
   persona they are the service's own, which holds its settings (st_valid_lnm_table). */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_lnm.h"

#define MAX_NAMES 2000
/* And at most this much JSON: a response over 4 MB is refused whole (st_http.c), so
   a listing stops here and says it was cut short, whatever the names' sizes. */
#define MAX_BYTES (3 * 1024 * 1024 + 512 * 1024)

/* The privileges switched on in the session (D9), for the helper to switch on too:
   it is a fresh login, with the account's defaults only. "-" for none. */
void svc_session_privs(const st_ctx *c, char *out, size_t outlen)
{
    int bit;
    out[0] = '\0';
    for (bit = 0; svc_priv_name(bit); bit++)
        if (c->session.priv_enable[bit / 32] & (1u << (bit % 32))) {
            if (*out) st_append(out, outlen, ",");
            st_append(out, outlen, svc_priv_name(bit));
        }
    if (!*out) st_copy(out, outlen, "-");
}

static void attr_list(st_jw *w, const char *key, const char *list)
{
    st_jw_key(w, key);
    st_jw_arr(w);
    while (*list) {
        const char *comma = strchr(list, ',');
        size_t n = comma ? (size_t) (comma - list) : strlen(list);
        if (n) st_jw_strn(w, list, n);
        list += n + (comma ? 1 : 0);
    }
    st_jw_arr_end(w);
}

static void name_json(st_jw *w, const st_lnm *n)
{
    int i;
    st_jw_obj(w);
    st_jw_kstr(w, "name", n->name);
    st_jw_kstr(w, "mode", n->mode);
    attr_list(w, "attributes", n->attributes);
    st_jw_key(w, "equivalences");
    st_jw_arr(w);
    for (i = 0; i < n->neq; i++) {
        st_jw_obj(w);
        st_jw_kstr(w, "value", n->eq[i].value);
        attr_list(w, "attributes", n->eq[i].attributes);
        st_jw_obj_end(w);
    }
    st_jw_arr_end(w);
    if (n->more) st_jw_kint(w, "more_equivalences", n->more);
    st_jw_obj_end(w);
}

/* The kind of a table, from its name and attributes: for grouping in the view. */
static const char *table_kind(const char *name, const char *attrs)
{
    if (!strcmp(name, "LNM$SYSTEM_TABLE")) return "system";
    if (!strcmp(name, "LNM$SYSCLUSTER_TABLE") || strstr(attrs, "clusterwide")) return "cluster";
    if (!strncmp(name, "LNM$GROUP_", 10)) return "group";
    if (!strncmp(name, "LNM$JOB_", 8)) return "job";
    return "other";
}

/* ---- the tables ---- */

typedef struct { st_jw *w; int n, truncated; } tables_ctx;

static int table_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    tables_ctx *tc = ctx;
    char table[ST_LNM_TABLE_MAX + 1];
    (void) t;
    /* In the directory, a table is a name with the "table" attribute. Process and job
       tables of this process never appear here: they are in the process directory. */
    if (!strstr(n->attributes, "table")) return 0;
    if (strlen(n->name) > ST_LNM_TABLE_MAX) return 0;
    if (tc->w->b->len > MAX_BYTES) { tc->truncated = 1; return 1; }
    st_jw_obj(tc->w);
    st_jw_kstr(tc->w, "name", n->name);
    st_jw_kstr(tc->w, "mode", n->mode);
    st_jw_kstr(tc->w, "kind", table_kind(n->name, n->attributes));
    st_jw_kbool(tc->w, "listable", st_valid_lnm_table(n->name, table));
    st_jw_obj_end(tc->w);
    if (++tc->n < MAX_NAMES) return 0;
    tc->truncated = 1;
    return 1;
}

void svc_logical_tables(st_ctx *c)
{
    st_whoami me;
    st_err e;
    st_jw w;
    tables_ctx tc;
    char group[24], privs[512];
    if (st_plat_whoami(&me, &e)) { st_app_error(c, &e); return; }
    snprintf(group, sizeof group, "LNM$GROUP_%06o", me.uic >> 16);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "your_group_table", group);
    st_jw_key(&w, "tables");
    st_jw_arr(&w);
    tc.w = &w;
    tc.n = tc.truncated = 0;
    svc_session_privs(c, privs, sizeof privs);
    if (st_plat_lnm_list("LNM$SYSTEM_DIRECTORY", "*", privs, table_cb, &tc, &e)) {
        st_jw_arr_end(&w);
        st_jw_obj_end(&w);
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", tc.truncated);
    st_jw_obj_end(&w);
}

/* ---- the names in a table ---- */

typedef struct { st_jw *w; char table[ST_LNM_TABLE_MAX + 1]; int tables, n, truncated; } names_ctx;

static int names_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    names_ctx *nc = ctx;
    if (nc->n >= MAX_NAMES || nc->w->b->len > MAX_BYTES) { nc->truncated = 1; return 1; }
    if (!nc->tables || strcmp(nc->table, t->name)) {   /* a search list: a new table begins */
        if (nc->tables) { st_jw_arr_end(nc->w); st_jw_obj_end(nc->w); }
        st_copy(nc->table, sizeof nc->table, t->name);
        st_jw_obj(nc->w);
        st_jw_kstr(nc->w, "name", t->name);
        st_jw_kstr(nc->w, "mode", t->mode);
        attr_list(nc->w, "attributes", t->attributes);
        st_jw_kstr(nc->w, "protection", t->protection);
        st_jw_kstr(nc->w, "owner", t->owner);
        st_jw_key(nc->w, "names");
        st_jw_arr(nc->w);
        nc->tables++;
    }
    name_json(nc->w, n);
    nc->n++;
    return 0;
}

void svc_logicals(st_ctx *c)
{
    char raw[96], table[ST_LNM_TABLE_MAX + 1], pattern[ST_LNM_PATTERN_MAX + 1], privs[512];
    int got;
    names_ctx nc;
    st_err e;
    st_jw w;

    if ((got = svc_query(c, "table", raw, sizeof raw)) < 0) return;
    if (!got) st_copy(raw, sizeof raw, "LNM$SYSTEM_TABLE");
    if (!st_valid_lnm_table(raw, table)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad table",
                        "A table name: A-Z, 0-9, $ and _. Process and job tables are not shown: here they would be the service's own.", 0, NULL);
        return;
    }
    if ((got = svc_query(c, "filter", raw, sizeof raw)) < 0) return;
    if (!got || !*raw) st_copy(raw, sizeof raw, "*");
    else if (!strchr(raw, '*') && !strchr(raw, '%')) {   /* plain text: anywhere in the name */
        char sub[96];
        if (strlen(raw) > ST_LNM_PATTERN_MAX - 2) {   /* refused, not cut: it would match more */
            st_resp_problem(c->resp, 400, "bad-request", "Bad filter",
                            "Plain text is at most 61 characters (a pattern, 63).", 0, NULL);
            return;
        }
        snprintf(sub, sizeof sub, "*%s*", raw);
        st_copy(raw, sizeof raw, sub);
    }
    if (!st_valid_lnm_pattern(raw, pattern)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad filter",
                        "A name or a pattern: A-Z, 0-9, $ and _, with * and % as wildcards.", 0, NULL);
        return;
    }
    memset(&nc, 0, sizeof nc);
    st_resp_json(c->resp, 200, &w);
    nc.w = &w;
    st_jw_obj(&w);
    st_jw_kstr(&w, "table", table);
    st_jw_kstr(&w, "filter", pattern);
    st_jw_key(&w, "tables");
    st_jw_arr(&w);
    svc_session_privs(c, privs, sizeof privs);
    if (st_plat_lnm_list(table, pattern, privs, names_cb, &nc, &e)) {
        st_app_error(c, &e);
        return;
    }
    if (nc.tables) { st_jw_arr_end(&w); st_jw_obj_end(&w); }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", nc.truncated);
    st_jw_obj_end(&w);
}

/* ---- one name ---- */

/* Where a name's equivalence is looked up next, as SHOW LOGICAL iterates, but never
   in the process or job table (the service's own): the viewer's group table, then the
   system-wide ones. */
static int translate(const char *group, const char *name, st_lnm *out, char *table)
{
    const char *tables[3];
    int i;
    st_err e;
    tables[0] = group; tables[1] = "LNM$SYSTEM_TABLE"; tables[2] = "LNM$SYSCLUSTER_TABLE";
    for (i = 0; i < 3; i++)
        if (st_plat_lnm_get(tables[i], name, -1, out, table, &e) == 1) return 1;
    return 0;
}

/* The logical name a value leads to, as file parsing would take it: the whole value
   if it is a bare name ("SYS$COMMON"), or the device part before a colon that ends
   it or starts a directory ("SYS$COMMON:", "PROJECT_DATA:[LOG]"). Anything else
   ("a b", "NODE::X") leads nowhere. */
static int next_name(const char *value, char *out, size_t outlen)
{
    const char *colon = strchr(value, ':');
    size_t n = colon ? (size_t) (colon - value) : strlen(value), i;
    if (colon && colon[1] && colon[1] != '[' && colon[1] != '<') return 0;
    if (!n || n >= outlen) return 0;
    for (i = 0; i < n; i++)
        if (!((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '$' || value[i] == '_' || value[i] == '-'))
            return 0;
    memcpy(out, value, n);
    out[n] = '\0';
    return 1;
}

static int bad_table_name(st_ctx *c, const char *rawtable, const char *name,
                          char table[ST_LNM_TABLE_MAX + 1])
{
    if (!st_valid_lnm_table(rawtable, table)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad table",
                        "A shareable table: process and job tables are not shown.", 0, NULL);
        return 1;
    }
    if (!st_valid_lnm_name(name)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad name", "1 to 255 printable characters.", 0, NULL);
        return 1;
    }
    return 0;
}

/* The viewer's group table: LNM$GROUP under a persona would be the service's. */
static int group_table(st_ctx *c, char group[24])
{
    st_whoami me;
    st_err e;
    if (st_plat_whoami(&me, &e)) { st_app_error(c, &e); return -1; }
    snprintf(group, 24, "LNM$GROUP_%06o", me.uic >> 16);
    return 0;
}

static void modes_json(st_jw *w, const char *key, int bits, int from)
{
    int m;
    st_jw_key(w, key);
    st_jw_arr(w);
    for (m = 3; m >= from; m--)
        if (bits & (1 << m)) st_jw_str(w, st_lnm_mode_name(m));
    st_jw_arr_end(w);
}

/* One name, its modes and its translation chain, answered with status. The table has
   passed st_valid_lnm_table, the name st_valid_lnm_name. */
static void one_name(st_ctx *c, const char *table, const char *name, int mode, int status)
{
    static st_lnm n, step;
    char found[ST_LNM_TABLE_MAX + 1], group[24];
    st_err e;
    st_jw w;
    int rc, i, modes;

    if (group_table(c, group)) return;
    rc = st_plat_lnm_get(!strcmp(table, "LNM$GROUP") ? group : table, name, mode, &n, found, &e);
    if (rc <= 0) { st_app_error(c, &e); return; }
    /* SHOW LOGICAL shows the outermost mode only; a name may be at others too. */
    if ((modes = st_plat_lnm_modes(found, name, &e)) < 0) modes = 0;

    st_resp_json(c->resp, status, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "table", found);
    st_jw_key(&w, "logical");
    name_json(&w, &n);
    modes_json(&w, "modes", modes, 0);
    st_jw_key(&w, "translations");
    st_jw_arr(&w);
    for (i = 0; i < n.neq; i++) {
        char next[ST_LNM_NAME_MAX + 1], where[ST_LNM_TABLE_MAX + 1];
        int depth;
        st_jw_arr(&w);
        st_copy(next, sizeof next, "");
        if (!strstr(n.eq[i].attributes, "terminal") && next_name(n.eq[i].value, next, sizeof next)) {
            for (depth = 0; depth < 9 && translate(group, next, &step, where); depth++) {
                st_jw_obj(&w);
                st_jw_kstr(&w, "name", step.name);
                st_jw_kstr(&w, "table", where);
                st_jw_kstr(&w, "value", step.neq ? step.eq[0].value : "");
                attr_list(&w, "attributes", step.neq ? step.eq[0].attributes : "");
                st_jw_obj_end(&w);
                if (!step.neq || strstr(step.eq[0].attributes, "terminal") ||
                    !next_name(step.eq[0].value, next, sizeof next)) break;
            }
        }
        st_jw_arr_end(&w);
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

void svc_logical_get(st_ctx *c)
{
    char table[ST_LNM_TABLE_MAX + 1];
    if (bad_table_name(c, c->args[0], c->args[1], table)) return;
    one_name(c, table, c->args[1], -1, 200);
}

/* GET api/v1/logical?table=&name=[&mode=]: as logicals/{table}/{name}, for any name,
   "/" too; with mode, the definition at that mode rather than the outermost. */
void svc_logical_one(st_ctx *c)
{
    char raw[40], table[ST_LNM_TABLE_MAX + 1], name[ST_LNM_NAME_MAX + 1], mraw[16];
    int gt, gn, gm, mode = -1;
    if ((gt = svc_query(c, "table", raw, sizeof raw)) < 0 || (gn = svc_query(c, "name", name, sizeof name)) < 0 ||
        (gm = svc_query(c, "mode", mraw, sizeof mraw)) < 0)
        return;
    if (!gt || !gn) {
        st_resp_problem(c->resp, 400, "bad-request", "table and name are required", NULL, 0, NULL);
        return;
    }
    if (bad_table_name(c, raw, name, table)) return;
    if (gm && (mode = st_lnm_mode(mraw)) < 0) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad mode", "user, super or exec.", 0, NULL);
        return;
    }
    one_name(c, table, name, mode, 200);
}

/* ---- changes (Phase 7b, D15) ---- */

/* PUT api/v1/logical {"table", "name", "mode", "attributes", "equivalences",
   "replace"}: define, or replace with "replace": true. 201 defined, 200 replaced. */
void svc_logical_define(st_ctx *c)
{
    static st_lnm_def d;
    st_jdoc doc;
    const char *why;
    char group[24], target[ST_LNM_TABLE_MAX + ST_LNM_NAME_MAX + 16];
    int rc, modes, replaced;
    st_err e;

    if (st_app_body(c, &doc)) return;
    if (!doc.root || doc.root->type != ST_JOBJ) {
        st_json_free(&doc);
        st_resp_problem(c->resp, 400, "bad-request", "The body must be a JSON object", NULL, 0, NULL);
        return;
    }
    rc = st_lnm_def_parse(doc.root, &d, &why);
    st_json_free(&doc);
    if (rc) { st_resp_problem(c->resp, 422, "invalid-value", "Invalid value", why, 0, NULL); return; }
    if (!strcmp(d.table, "LNM$GROUP")) {
        if (group_table(c, group)) return;
        st_copy(d.table, sizeof d.table, group);
    }
    snprintf(target, sizeof target, "%s %s %s", d.table, d.name, st_lnm_mode_name(d.mode));
    if ((modes = st_plat_lnm_modes(d.table, d.name, &e)) < 0) { st_app_error(c, &e); return; }
    if ((modes & (1 << d.mode)) && !d.replace) {
        st_resp_problem(c->resp, 409, "exists", "The name exists at that mode",
                        "Send \"replace\": true to replace it.", 0, NULL);
        return;
    }
    /* Never the equivalences in the audit log: names sometimes carry secrets. */
    if (st_plat_lnm_define(&d, &e) < 0) {
        st_app_audit(c, c->session.username, "logical-define", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    /* Replaced if it was there at that mode. Not OpenVMS's SUPERSEDE: it says that
       too when no_alias removes the name at an outer mode (NOTES.md). */
    replaced = (modes & (1 << d.mode)) != 0;
    st_app_audit(c, c->session.username, "logical-define", target, "ok", replaced ? "replaced" : NULL);
    one_name(c, d.table, d.name, d.mode, replaced ? 200 : 201);
}

/* DELETE api/v1/logical?table=&name=&mode=: the name at that mode and every outer
   one, as DEASSIGN. The answer names the modes removed. */
void svc_logical_deassign(st_ctx *c)
{
    char raw[40], table[ST_LNM_TABLE_MAX + 1], name[ST_LNM_NAME_MAX + 1], mraw[16], group[24];
    char target[ST_LNM_TABLE_MAX + ST_LNM_NAME_MAX + 16];
    int mode, modes, gt, gn, gm;
    st_err e;
    st_jw w;

    if ((gt = svc_query(c, "table", raw, sizeof raw)) < 0 || (gn = svc_query(c, "name", name, sizeof name)) < 0 ||
        (gm = svc_query(c, "mode", mraw, sizeof mraw)) < 0)
        return;
    if (!gt || !gn || !gm) {
        st_resp_problem(c->resp, 400, "bad-request", "table, name and mode are required", NULL, 0, NULL);
        return;
    }
    if (bad_table_name(c, raw, name, table)) return;
    if ((mode = st_lnm_mode(mraw)) < 0) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad mode", "user, super or exec.", 0, NULL);
        return;
    }
    if (!strcmp(table, "LNM$GROUP")) {
        if (group_table(c, group)) return;
        st_copy(table, sizeof table, group);
    }
    snprintf(target, sizeof target, "%s %s %s", table, name, st_lnm_mode_name(mode));
    if ((modes = st_plat_lnm_modes(table, name, &e)) < 0) { st_app_error(c, &e); return; }
    if (st_plat_lnm_deassign(table, name, mode, &e)) {
        st_app_audit(c, c->session.username, "logical-deassign", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "logical-deassign", target, "ok", NULL);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "table", table);
    st_jw_kstr(&w, "name", name);
    modes_json(&w, "removed", modes, mode);
    st_jw_obj_end(&w);
}
