/* svc_products.c - installed products, read-only (Phase 12, D20).

   GET api/v1/products    what PCSI has installed, its install and remove history, and
                          VMSINSTAL's history of installs

   PCSI has no documented interface to its database, so the D14 helper process, which
   is the viewer, runs PRODUCT SHOW and Steward parses it (st_product.c); PRODUCT needs
   SYSLCK, and a refusal is shown as OpenVMS gives it (D10). VMSINSTAL keeps its own
   record, a text file read in-process as the viewer. It records installs only, so it
   is history, not a list of what is installed now. */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_product.h"

#define MAX_ROWS 5000   /* each part */

static const char *const part_keys[ST_PROD_PARTS] = { "products", "history" };

typedef struct { st_jw *w; int open, n[ST_PROD_PARTS], nv, truncated; } prod_ctx;

/* "A, B, C" (as the parser joins a list column) as a JSON array. */
static void list(st_jw *w, const char *key, const char *joined)
{
    const char *s = joined;
    st_jw_key(w, key);
    st_jw_arr(w);
    while (*s) {
        const char *e = strstr(s, ", ");
        char item[160];
        size_t n = e ? (size_t) (e - s) : strlen(s);
        if (n >= sizeof item) n = sizeof item - 1;
        memcpy(item, s, n);
        item[n] = '\0';
        if (n) st_jw_str(w, item);
        if (!e) break;
        s = e + 2;
    }
    st_jw_arr_end(w);
}

static void open_part(prod_ctx *pc, int part)
{
    while (pc->open < part) {   /* products, then history: each opened once, in order */
        if (pc->open >= 0) st_jw_arr_end(pc->w);
        pc->open++;
        st_jw_key(pc->w, part_keys[pc->open]);
        st_jw_arr(pc->w);
    }
}

static int prod_one(const st_product *r, void *ctx)
{
    prod_ctx *pc = ctx;
    if (r->part < 0 || r->part >= ST_PROD_PARTS || r->part < pc->open) return 0;   /* out of order: dropped */
    open_part(pc, r->part);
    if (pc->n[r->part] >= MAX_ROWS) { pc->truncated = 1; return 0; }   /* drains */
    pc->n[r->part]++;
    st_jw_obj(pc->w);
    st_jw_kstr(pc->w, "producer", r->producer);
    st_jw_kstr(pc->w, "base", r->base);
    st_jw_kstr(pc->w, "name", r->name);
    st_jw_kstr(pc->w, "version", r->version);
    st_jw_kstr(pc->w, "kit_type", r->kit_type);
    if (r->part == ST_PROD_PRODUCTS) {
        st_jw_kstr(pc->w, "state", r->state);
        list(pc->w, "maintenance", r->maintenance);
        list(pc->w, "referenced_by", r->referenced_by);
    } else {
        st_jw_kstr(pc->w, "operation", r->operation);
        st_jw_kstr(pc->w, "validation", r->validation);
        st_jw_kstr(pc->w, "date", r->date);
        st_jw_kstr(pc->w, "error", r->error);
        st_jw_kstr(pc->w, "user", r->user);
        st_jw_kstr(pc->w, "remark", r->remark);
    }
    st_jw_obj_end(pc->w);
    return 0;
}

static int vmsinstal_one(const st_vmsinstal *v, void *ctx)
{
    prod_ctx *pc = ctx;
    if (pc->nv >= MAX_ROWS) { pc->truncated = 1; return 1; }
    pc->nv++;
    st_jw_obj(pc->w);
    st_jw_kstr(pc->w, "name", v->name);
    st_jw_kstr(pc->w, "mnemonic", v->mnemonic);
    st_jw_kstr(pc->w, "version", v->version);
    st_jw_kstr(pc->w, "date", v->date);
    st_jw_kstr(pc->w, "status", v->status);
    st_jw_kstr(pc->w, "ivp", v->ivp);
    st_jw_kstr(pc->w, "node", v->node);
    st_jw_kstr(pc->w, "installer", v->installer);
    st_jw_kstr(pc->w, "signature", v->signature);
    st_jw_obj_end(pc->w);
    return 0;
}

static void source(st_jw *w, const char *key, int read, int seen, unsigned int cond, const char *text)
{
    st_jw_key(w, key);
    st_jw_obj(w);
    st_jw_kbool(w, "read", read);
    if (!read && seen) {
        char hex[16];
        snprintf(hex, sizeof hex, "%%X%08X", cond);
        st_jw_kstr(w, "vms_status", hex);
        st_jw_kstr(w, "vms_message", text);
    }
    st_jw_obj_end(w);
}

void svc_products(st_ctx *c)
{
    static st_product_parser p;   /* a few KB: not on the stack */
    static char text[ST_PROD_PARTS][256];
    char privs[512], vtext[256];
    unsigned int vcond = 0;
    prod_ctx pc;
    st_err e;
    st_jw w;
    int i;

    memset(&pc, 0, sizeof pc);
    pc.open = -1;
    svc_session_privs(c, privs, sizeof privs);
    st_resp_json(c->resp, 200, &w);
    pc.w = &w;
    st_jw_obj(&w);
    st_product_init(&p, prod_one, &pc);
    if (st_plat_product_list(privs, &p, text, &e)) { st_app_error(c, &e); return; }
    open_part(&pc, ST_PROD_HISTORY);   /* both arrays, empty where nothing came */
    st_jw_arr_end(&w);

    st_jw_key(&w, "vmsinstal");
    st_jw_arr(&w);
    if (st_plat_vmsinstal(vmsinstal_one, &pc, &vcond, vtext, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", pc.truncated);

    /* Each source: read, or OpenVMS's refusal (as access history shows its sources). */
    st_jw_key(&w, "sources");
    st_jw_obj(&w);
    for (i = 0; i < ST_PROD_PARTS; i++)
        source(&w, part_keys[i], st_product_ok(&p, i), p.seen[i], p.status[i], text[i]);
    source(&w, "vmsinstal", vcond == 0, 1, vcond, vtext);
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}
