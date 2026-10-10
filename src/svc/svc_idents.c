/* svc_idents.c - rights identifiers (RIGHTSLIST), read-only: list, detail, holders.

   As with users, everything runs under the caller's persona (D2) and OpenVMS
   decides what may be read. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

/* Indexed by ST_IA_*; the names AUTHORIZE uses. */
static const char *const attrib_names[ST_IA_COUNT] = {
    "RESOURCE", "DYNAMIC", "NOACCESS", "SUBSYSTEM", "IMPERSONATE", "HOLDER_HIDDEN",
    "NAME_HIDDEN"
};

/* The rights database is read whole and sorted by name, as AUTHORIZE lists it: its
   own order is by value. Past this many the list says it is truncated. */
#define MAX_IDENTS 8192

void svc_ident_value_text(unsigned int value, char out[24])
{
    if (value & ST_IDENT_GENERAL) snprintf(out, 24, "%%X%08X", value);
    else svc_uic_text(value, out);
}

void svc_ident_attrib_json(st_jw *w, const char *key, unsigned int attrib)
{
    int i;
    st_jw_key(w, key);
    st_jw_arr(w);
    for (i = 0; i < ST_IA_COUNT; i++)
        if (attrib & (1u << i)) st_jw_str(w, attrib_names[i]);
    st_jw_arr_end(w);
}

static int check_ident(const char *in, char out[32])
{
    return st_valid_ident(in, out);
}

static void ident_json(st_jw *w, const st_ident *id)
{
    char v[24];
    svc_ident_value_text(id->value, v);
    st_jw_kstr(w, "name", id->name);
    st_jw_kstr(w, "value", v);
    st_jw_kstr(w, "type", (id->value & ST_IDENT_GENERAL) ? "general" : "uic");
    svc_ident_attrib_json(w, "attributes", id->attrib);
}

/* ---------------------------------------------------------------- list */

enum { T_GENERAL, T_UIC, T_ALL };

typedef struct {
    st_ident   *ids;
    size_t      n;
    int         truncated;
    int         type;
    const char *filter;
    const char *after;
} collect_state;

static int collect_one(const st_ident *id, void *ctx)
{
    collect_state *s = ctx;
    int general = (id->value & ST_IDENT_GENERAL) != 0;
    if ((s->type == T_GENERAL && !general) || (s->type == T_UIC && general)) return 0;
    if (*s->after && strcmp(id->name, s->after) <= 0) return 0;
    if (!st_filter_match(s->filter, id->name, NULL)) return 0;
    if (s->n == MAX_IDENTS) { s->truncated = 1; return 1; }
    s->ids[s->n++] = *id;
    return 0;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const st_ident *) a)->name, ((const st_ident *) b)->name);
}

/* GET api/v1/identifiers?type=general|uic|all&filter=&after=&limit= */
void svc_idents_list(st_ctx *c)
{
    static st_ident ids[MAX_IDENTS];   /* one request at a time per process */
    char filter[32], after[32], type[16];
    collect_state s;
    int limit;
    size_t i;
    st_err e;
    st_jw w;

    memset(&s, 0, sizeof s);
    if (svc_list_query(c, filter, after, &limit, check_ident)) return;
    s.type = T_GENERAL;
    switch (svc_query(c, "type", type, sizeof type)) {
    case -1: return;
    case 0:  break;
    default:
        if (!strcmp(type, "general")) s.type = T_GENERAL;
        else if (!strcmp(type, "uic")) s.type = T_UIC;
        else if (!strcmp(type, "all")) s.type = T_ALL;
        else {
            st_resp_problem(c->resp, 400, "bad-request", "Bad type",
                            "type is general, uic or all.", 0, NULL);
            return;
        }
    }
    s.ids = ids;
    s.filter = filter;
    s.after = after;
    if (st_plat_ident_enum(collect_one, &s, &e)) { st_app_error(c, &e); return; }
    qsort(ids, s.n, sizeof ids[0], by_name);

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "identifiers");
    st_jw_arr(&w);
    for (i = 0; i < s.n && i < (size_t) limit; i++) {
        st_jw_obj(&w);
        ident_json(&w, &ids[i]);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    if (s.n > (size_t) limit) st_jw_kstr(&w, "next", ids[limit - 1].name);
    else { st_jw_key(&w, "next"); st_jw_null(&w); }
    if (s.truncated) st_jw_kbool(&w, "truncated", 1);
    st_jw_obj_end(&w);
}

/* ---------------------------------------------------------------- detail */

static int ident_arg(st_ctx *c, char name[32])
{
    if (!st_valid_ident(c->args[0], name)) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "Not a valid identifier name.", 0, NULL);
        return -1;
    }
    return 0;
}

/* GET api/v1/identifiers/{id} */
void svc_ident_get(st_ctx *c)
{
    char name[32];
    st_ident id;
    st_err e;
    st_jw w;

    if (ident_arg(c, name)) return;
    if (st_plat_ident_get(name, &id, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    ident_json(&w, &id);
    st_jw_obj_end(&w);
}

typedef struct { st_jw *w; int count; } holders_state;

static int holder_one(const st_ident *h, void *ctx)
{
    holders_state *s = ctx;
    char uic[24];
    if (s->count++ >= 65536) return 1;
    svc_uic_text(h->value, uic);
    st_jw_obj(s->w);
    st_jw_key(s->w, "username");   /* the holder's UIC identifier, normally the username */
    if (*h->name) st_jw_str(s->w, h->name); else st_jw_null(s->w);
    st_jw_kstr(s->w, "uic", uic);
    svc_ident_attrib_json(s->w, "attributes", h->attrib);
    st_jw_obj_end(s->w);
    return 0;
}

/* GET api/v1/identifiers/{id}/holders */
void svc_ident_holders(st_ctx *c)
{
    char name[32];
    st_ident id;
    st_err e;
    st_jw w;
    holders_state s;

    if (ident_arg(c, name)) return;
    if (st_plat_ident_get(name, &id, &e)) { st_app_error(c, &e); return; }
    s.w = &w;
    s.count = 0;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "name", id.name);
    st_jw_key(&w, "holders");
    st_jw_arr(&w);
    if (st_plat_ident_holders(id.value, holder_one, &s, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}
