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

/* The privileges switched on in the session (D9), for the helper to switch on too:
   it is a fresh login, with the account's defaults only. "-" for none. */
static void session_privs(const st_ctx *c, char *out, size_t outlen)
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

typedef struct { st_jw *w; int n; } tables_ctx;

static int table_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    tables_ctx *tc = ctx;
    char table[ST_LNM_TABLE_MAX + 1];
    (void) t;
    /* In the directory, a table is a name with the "table" attribute. Process and job
       tables of this process never appear here: they are in the process directory. */
    if (!strstr(n->attributes, "table")) return 0;
    if (strlen(n->name) > ST_LNM_TABLE_MAX) return 0;
    st_jw_obj(tc->w);
    st_jw_kstr(tc->w, "name", n->name);
    st_jw_kstr(tc->w, "mode", n->mode);
    st_jw_kstr(tc->w, "kind", table_kind(n->name, n->attributes));
    st_jw_kbool(tc->w, "listable", st_valid_lnm_table(n->name, table));
    st_jw_obj_end(tc->w);
    return ++tc->n >= MAX_NAMES;
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
    tc.n = 0;
    session_privs(c, privs, sizeof privs);
    if (st_plat_lnm_list("LNM$SYSTEM_DIRECTORY", "*", privs, table_cb, &tc, &e)) {
        st_jw_arr_end(&w);
        st_jw_obj_end(&w);
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

/* ---- the names in a table ---- */

typedef struct { st_jw *w; char table[ST_LNM_TABLE_MAX + 1]; int tables, n, truncated; } names_ctx;

static int names_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    names_ctx *nc = ctx;
    if (nc->n >= MAX_NAMES) { nc->truncated = 1; return 1; }
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
        if (strlen(raw) > ST_LNM_PATTERN_MAX - 2) raw[ST_LNM_PATTERN_MAX - 2] = '\0';
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
    session_privs(c, privs, sizeof privs);
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
        if (st_plat_lnm_get(tables[i], name, out, table, &e) == 1) return 1;
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

void svc_logical_get(st_ctx *c)
{
    static st_lnm n, step;
    char table[ST_LNM_TABLE_MAX + 1], found[ST_LNM_TABLE_MAX + 1], group[24];
    st_whoami me;
    st_err e;
    st_jw w;
    int rc, i;

    if (!st_valid_lnm_table(c->args[0], table)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad table",
                        "A shareable table: process and job tables are not shown.", 0, NULL);
        return;
    }
    if (!st_valid_lnm_name(c->args[1])) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad name", "1 to 255 printable characters.", 0, NULL);
        return;
    }
    if (st_plat_whoami(&me, &e)) { st_app_error(c, &e); return; }
    snprintf(group, sizeof group, "LNM$GROUP_%06o", me.uic >> 16);
    rc = st_plat_lnm_get(!strcmp(table, "LNM$GROUP") ? group : table, c->args[1], &n, found, &e);
    if (rc <= 0) { st_app_error(c, &e); return; }

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "table", found);
    st_jw_key(&w, "logical");
    name_json(&w, &n);
    /* Each equivalence, translated in turn while it names another logical, up to the
       nine levels OpenVMS itself follows, stopping at a terminal one. */
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
