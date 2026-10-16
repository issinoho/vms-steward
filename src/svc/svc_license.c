/* svc_license.c - licences, read-only (Phase 11, D19).

   GET api/v1/licenses    the licences loaded on this node, its charge, and the
                          licence database where the viewer may read it

   OpenVMS has no documented service that lists licences, so the D14 helper process,
   which is the viewer, runs SHOW LICENSE and LICENSE LIST and Steward parses them
   (st_license.c). Any user may SHOW LICENSE; the database is as LMF$LICENSE's
   protection allows, and a refusal is shown as OpenVMS gives it (D10). */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_license.h"

#define MAX_LICENSES 2000   /* each part */

static const char *const part_keys[ST_LIC_PARTS] = { "loaded", "charge", "database" };

typedef struct { st_jw *w; int open, n[ST_LIC_PARTS], truncated; } lic_ctx;

static void kstr_if(st_jw *w, const char *key, const char *v, int db)
{
    if (db) st_jw_kstr(w, key, v);
}

static int lic_one(const st_license *l, void *ctx)
{
    lic_ctx *lc = ctx;
    int db = l->part == ST_LIC_DATABASE, i;
    if ((l->part != ST_LIC_LOADED && !db) || l->part < lc->open) return 0;   /* out of order: never written twice */
    if (l->part != lc->open) {   /* the loaded licences come first, then the database */
        if (lc->open >= 0) st_jw_arr_end(lc->w);
        else if (db) { st_jw_key(lc->w, "loaded"); st_jw_arr(lc->w); st_jw_arr_end(lc->w); }   /* none loaded */
        st_jw_key(lc->w, part_keys[l->part]);
        st_jw_arr(lc->w);
        lc->open = l->part;
    }
    if (lc->n[l->part] >= MAX_LICENSES) { lc->truncated = 1; return 0; }   /* drains */
    lc->n[l->part]++;
    st_jw_obj(lc->w);
    st_jw_kstr(lc->w, "product", l->product);
    st_jw_kstr(lc->w, "producer", l->producer);
    kstr_if(lc->w, "issuer", l->issuer, db);
    kstr_if(lc->w, "authorization", l->authorization, db);
    st_jw_kstr(lc->w, "units", l->units);
    st_jw_kstr(lc->w, "version", l->version);
    st_jw_kstr(lc->w, "release", l->release);
    st_jw_kstr(lc->w, "termination", l->termination);
    st_jw_kstr(lc->w, "availability", l->availability);
    st_jw_kstr(lc->w, "activity", l->activity);
    if (!db) st_jw_kbool(lc->w, "per_core", l->per_core);
    st_jw_kstr(lc->w, "options", l->options);
    kstr_if(lc->w, "hardware_id", l->hardware_id, db);
    kstr_if(lc->w, "revision", l->revision, db);
    kstr_if(lc->w, "status", l->status, db);
    kstr_if(lc->w, "command", l->command, db);
    kstr_if(lc->w, "modified_by", l->modified_by, db);
    kstr_if(lc->w, "modified_on", l->modified_on, db);
    st_jw_key(lc->w, "other");
    st_jw_arr(lc->w);
    for (i = 0; i < l->nother; i++) {
        st_jw_obj(lc->w);
        st_jw_kstr(lc->w, "label", l->other_label[i]);
        st_jw_kstr(lc->w, "value", l->other_value[i]);
        st_jw_obj_end(lc->w);
    }
    st_jw_arr_end(lc->w);
    st_jw_obj_end(lc->w);
    return 0;
}

void svc_licenses(st_ctx *c)
{
    static st_license_parser p;   /* a few KB: not on the stack */
    static char text[ST_LIC_PARTS][256];
    char privs[512];
    lic_ctx lc;
    st_err e;
    st_jw w;
    int i;

    memset(&lc, 0, sizeof lc);
    lc.open = -1;
    svc_session_privs(c, privs, sizeof privs);
    st_resp_json(c->resp, 200, &w);
    lc.w = &w;
    st_jw_obj(&w);
    st_license_init(&p, lic_one, &lc);
    if (st_plat_license_list(privs, &p, text, &e)) { st_app_error(c, &e); return; }
    /* Both arrays, empty where nothing came. */
    if (lc.open == ST_LIC_LOADED) st_jw_arr_end(&w);
    if (lc.open < 0) { st_jw_key(&w, "loaded"); st_jw_arr(&w); st_jw_arr_end(&w); }
    if (lc.open != ST_LIC_DATABASE) { st_jw_key(&w, "database"); st_jw_arr(&w); }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", lc.truncated);
    st_jw_kstr(&w, "node", p.node);

    st_jw_key(&w, "charge");
    st_jw_obj(&w);
    st_jw_key(&w, "lines");
    st_jw_arr(&w);
    for (i = 0; i < p.ncharge; i++) st_jw_str(&w, p.charge[i]);
    st_jw_arr_end(&w);
    st_jw_kstr(&w, "type", p.charge_type);
    st_jw_kstr(&w, "units_required", p.charge_units);
    st_jw_obj_end(&w);

    st_jw_key(&w, "database_file");
    st_jw_obj(&w);
    st_jw_kstr(&w, "file", p.db_file);
    st_jw_kstr(&w, "created", p.db_created);
    st_jw_kstr(&w, "created_by", p.db_created_by);
    st_jw_kstr(&w, "lmf_version", p.db_version);
    st_jw_obj_end(&w);

    /* Each part: read, or OpenVMS's refusal (as access history shows its sources). */
    st_jw_key(&w, "sources");
    st_jw_obj(&w);
    for (i = 0; i < ST_LIC_PARTS; i++) {
        st_jw_key(&w, part_keys[i]);
        st_jw_obj(&w);
        st_jw_kbool(&w, "read", st_license_ok(&p, i));
        if (!st_license_ok(&p, i) && p.seen[i]) {
            char hex[16];
            snprintf(hex, sizeof hex, "%%X%08X", p.status[i]);
            st_jw_kstr(&w, "vms_status", hex);
            st_jw_kstr(&w, "vms_message", text[i]);
        }
        st_jw_obj_end(&w);
    }
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}
