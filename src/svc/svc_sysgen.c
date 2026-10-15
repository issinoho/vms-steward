/* svc_sysgen.c - system parameters, read-only (Phase 10, D18).

   GET api/v1/sysgen?filter=    every parameter, as SYSGEN SHOW/ALL prints it

   OpenVMS has no service that gives SYSGEN's defaults, limits and units, so the D14
   helper process, which is the viewer, runs SYSGEN SHOW/ALL and Steward parses it
   (st_sysgen.c). Any user may run SYSGEN SHOW at a terminal. */
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_sysgen.h"

#define MAX_PARAMS 2000

static void values_json(st_jw *w, const st_param_values *v)
{
    st_jw_kstr(w, "current", v->current);
    st_jw_kstr(w, "default", v->dflt);
    st_jw_kstr(w, "min", v->min);
    st_jw_kstr(w, "max", v->max);
    st_jw_kstr(w, "unit", v->unit);
}

typedef struct { st_jw *w; const char *filter; int n, truncated; } params_ctx;

static int param_one(const st_param *p, void *ctx)
{
    params_ctx *pc = ctx;
    if (*pc->filter && !st_filter_match(pc->filter, p->name, NULL)) return 0;
    if (pc->n >= MAX_PARAMS) { pc->truncated = 1; return 1; }
    st_jw_obj(pc->w);
    st_jw_kstr(pc->w, "name", p->name);
    values_json(pc->w, &p->v);
    st_jw_kbool(pc->w, "dynamic", p->dynamic);
    st_jw_kbool(pc->w, "ascii", p->ascii);
    if (p->has_internal) {
        st_jw_key(pc->w, "internal");
        st_jw_obj(pc->w);
        values_json(pc->w, &p->internal);
        st_jw_obj_end(pc->w);
    }
    st_jw_obj_end(pc->w);
    pc->n++;
    return 0;
}

void svc_sysgen(st_ctx *c)
{
    char raw[64], filter[ST_IDENT_MAX + 1] = "", privs[512];
    params_ctx pc;
    st_err e;
    st_jw w;
    int got;

    if ((got = svc_query(c, "filter", raw, sizeof raw)) < 0) return;
    if (got && *raw && !st_valid_filter(raw, filter)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad filter",
                        "Up to 31 printable characters; * and % are wildcards.", 0, NULL);
        return;
    }
    memset(&pc, 0, sizeof pc);
    pc.filter = filter;
    svc_session_privs(c, privs, sizeof privs);
    st_resp_json(c->resp, 200, &w);
    pc.w = &w;
    st_jw_obj(&w);
    st_jw_key(&w, "parameters");
    st_jw_arr(&w);
    if (st_plat_sysgen_list(privs, param_one, &pc, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", pc.truncated);
    st_jw_obj_end(&w);
}
