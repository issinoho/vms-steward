/* svc_products.c - installed products, read-only (Phase 12, D20).

   GET api/v1/products    what PCSI has installed, its install and remove history, and
                          VMSINSTAL's history of installs

   PCSI has no documented interface to its database, so the D14 helper process, which
   is the viewer, runs PRODUCT SHOW and Steward parses it (st_product.c); PRODUCT needs
   SYSLCK, and a refusal is shown as OpenVMS gives it (D10). VMSINSTAL keeps its own
   record, a text file read in-process as the viewer. It records installs only, so it
   is history, not a list of what is installed now.

   Installing and removing (12b, D26):
   GET  api/v1/products/kits?source=<dir>   the kits in a directory (PRODUCT FIND)
   POST api/v1/products/install             {"producer", "base", "name", "version",
                                             "source", "destination"?}
   POST api/v1/products/remove              {"producer", "base", "name"}
   GET  api/v1/products/log?name=<log>      the job's log, from the viewer's login
                                            directory
   The D14 helper, as the viewer, submits a batch job under the viewer's own name; the
   answer is its entry and its log (202). Steward refuses its own product and the
   operating system; OpenVMS decides the rest. Each request is audited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_product.h"

#define MAX_ROWS 5000   /* each part */

static const char *const part_keys[ST_PROD_PARTS] = { "products", "history", "kits" };

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
    if (r->part < 0 || r->part >= ST_PROD_KITS || r->part < pc->open) return 0;   /* out of order: dropped */
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
        const char *why = st_product_refused(r->producer, r->base, r->name);
        st_jw_kstr(pc->w, "state", r->state);
        if (why) st_jw_kstr(pc->w, "refused", why);   /* not removed by Steward (12b) */
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
    for (i = 0; i < ST_PROD_KITS; i++)   /* the list's two parts: kits are 12b's */
        source(&w, part_keys[i], st_product_ok(&p, i), p.seen[i], p.status[i], text[i]);
    source(&w, "vmsinstal", vcond == 0, 1, vcond, vtext);
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}

/* ---- installing and removing (12b, D26) ---- */

typedef struct { st_jw *w; int n; } kits_ctx;

static int kit_one(const st_product *r, void *ctx)
{
    kits_ctx *kc = ctx;
    const char *why;
    if (r->part != ST_PROD_KITS || kc->n >= MAX_ROWS) return 0;
    kc->n++;
    why = st_product_refused(r->producer, r->base, r->name);
    st_jw_obj(kc->w);
    st_jw_kstr(kc->w, "producer", r->producer);
    st_jw_kstr(kc->w, "base", r->base);
    st_jw_kstr(kc->w, "name", r->name);
    st_jw_kstr(kc->w, "version", r->version);
    st_jw_kstr(kc->w, "kit_type", r->kit_type);
    st_jw_kstr(kc->w, "kit_format", r->kit_format);
    if (why) st_jw_kstr(kc->w, "refused", why);
    st_jw_obj_end(kc->w);
    return 0;
}

void svc_product_kits(st_ctx *c)
{
    static st_product_parser p;
    char source[256], privs[512], text[256];
    kits_ctx kc;
    st_err e;
    st_jw w;
    int got = svc_query(c, "source", source, sizeof source);
    if (got < 0) return;
    if (!got || !st_valid_kit_dir(source)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad source directory",
                        "A directory such as DKA100:[KITS], in capitals.", 0, NULL);
        return;
    }
    svc_session_privs(c, privs, sizeof privs);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "source", source);
    st_jw_key(&w, "kits");
    st_jw_arr(&w);
    memset(&kc, 0, sizeof kc);
    kc.w = &w;
    st_product_init(&p, kit_one, &kc);
    if (st_plat_product_find(privs, source, &p, text, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    /* None found, or PRODUCT refused: its message, as PRODUCT printed it. */
    if (text[0]) st_jw_kstr(&w, "message", text);
    st_jw_obj_end(&w);
}

/* A string member, checked: 0, or -1 having answered 422. */
static int member(st_ctx *c, const st_jval *root, const char *key, int required,
                  int (*valid)(const char *), char *out, size_t outlen)
{
    const char *v = st_json_get_str(root, key);
    char d[96];
    out[0] = '\0';
    if (!v || !*v) {
        if (!required) return 0;
        snprintf(d, sizeof d, "%s is required.", key);
    } else if (strlen(v) >= outlen || !valid(v)) {
        snprintf(d, sizeof d, "%s: not a valid value.", key);
    } else {
        strcpy(out, v);
        return 0;
    }
    st_resp_problem(c->resp, 422, "invalid-value", "Invalid value", d, 0, NULL);
    return -1;
}

static int word31(const char *s) { return st_valid_pcsi_word(s, 31); }
static int word15(const char *s) { return st_valid_pcsi_word(s, 15); }
static int word47(const char *s) { return st_valid_pcsi_word(s, 47); }

static void product_job(st_ctx *c, int remove)
{
    st_pcsi_id id;
    char source[256], dest[256], privs[512], logname[40], target[160];
    const char *why, *action = remove ? "product-remove" : "product-install";
    unsigned int entry = 0;
    st_jdoc doc;
    st_err e;
    st_jw w;
    int bad;

    if (st_app_body(c, &doc)) return;
    if (!doc.root || doc.root->type != ST_JOBJ) {
        st_json_free(&doc);
        st_resp_problem(c->resp, 400, "bad-request", "The body must be a JSON object", NULL, 0, NULL);
        return;
    }
    memset(&id, 0, sizeof id);
    bad = member(c, doc.root, "producer", 1, word31, id.producer, sizeof id.producer) ||
          member(c, doc.root, "base", 1, word15, id.base, sizeof id.base) ||
          member(c, doc.root, "name", 1, word47, id.name, sizeof id.name) ||
          member(c, doc.root, "version", !remove, word31, id.version, sizeof id.version) ||
          member(c, doc.root, "source", !remove, st_valid_kit_dir, source, sizeof source) ||
          member(c, doc.root, "destination", 0, st_valid_kit_dir, dest, sizeof dest);
    st_json_free(&doc);
    if (bad) return;
    snprintf(target, sizeof target, "%s %s %s %s", id.producer, id.base, id.name, id.version);
    if ((why = st_product_refused(id.producer, id.base, id.name)) != NULL) {
        st_app_audit(c, c->session.username, action, target, "refused", why);
        st_resp_problem(c->resp, 409, "refused-product", "Steward will not do this", why, 0, NULL);
        return;
    }
    svc_session_privs(c, privs, sizeof privs);
    if (strlen(privs) > 255) {
        st_resp_problem(c->resp, 422, "too-many-privileges", "Too many privileges switched on",
                        "The job is given the privileges switched on as one DCL parameter, at most 255 characters. Switch on fewer.", 0, NULL);
        return;
    }
    if (st_plat_product_job(privs, remove, &id, remove ? "" : source, remove ? "" : dest, &entry, logname, &e)) {
        st_app_audit(c, c->session.username, action, target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    {
        char detail[80];
        snprintf(detail, sizeof detail, "entry %u, log %s", entry, logname);
        st_app_audit(c, c->session.username, action, target, "submitted", detail);
    }
    st_resp_json(c->resp, 202, &w);
    st_jw_obj(&w);
    st_jw_kint(&w, "entry", entry);
    st_jw_kstr(&w, "log", logname);
    st_jw_obj_end(&w);
}

void svc_product_install(st_ctx *c) { product_job(c, 0); }
void svc_product_remove(st_ctx *c) { product_job(c, 1); }

#define MAX_LOG_LINES 5000
typedef struct { st_jw *w; int n, done, truncated; char end[16]; } log_ctx;

static int log_line(const char *line, size_t len, void *ctx)
{
    log_ctx *lc = ctx;
    char buf[1024];
    if (len >= sizeof buf) len = sizeof buf - 1;
    memcpy(buf, line, len);
    buf[len] = '\0';
    if (!strncmp(buf, "%%PCSI-END%% ", 13)) {
        lc->done = 1;
        st_copy(lc->end, sizeof lc->end, buf + 13);
        return 0;
    }
    if (lc->n >= MAX_LOG_LINES) { lc->truncated = 1; return 0; }
    lc->n++;
    st_jw_str(lc->w, buf);
    return 0;
}

void svc_product_log(st_ctx *c)
{
    static st_user u;
    char name[40], spec[160];
    log_ctx lc;
    st_err e;
    st_jw w;
    int got = svc_query(c, "name", name, sizeof name);
    if (got < 0) return;
    if (!got || !st_valid_pcsi_log(name)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad log name", "STEWARD_PCSI_<yyyymmddhhmmss>.LOG.", 0, NULL);
        return;
    }
    /* The viewer's own login directory, from their own UAF record (a persona may read
       its own: PHASE1.md); never a directory the request names. */
    if (st_plat_user_get(c->session.username, &u, &e)) { st_app_error(c, &e); return; }
    snprintf(spec, sizeof spec, "%s%s%s", u.defdev, u.defdir, name);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "name", name);
    st_jw_key(&w, "lines");
    st_jw_arr(&w);
    memset(&lc, 0, sizeof lc);
    lc.w = &w;
    if (st_plat_text_file(spec, log_line, &lc, &e)) {
        if (e.kind == ST_E_NOTFOUND) {   /* the job has not started yet: no log so far */
            st_jw_arr_end(&w);
            st_jw_kbool(&w, "started", 0);
            st_jw_kbool(&w, "done", 0);
            st_jw_obj_end(&w);
            return;
        }
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "started", 1);
    st_jw_kbool(&w, "done", lc.done);
    if (lc.done) {
        char hex[16];
        unsigned int st = (unsigned int) strtoul(lc.end, NULL, 16);
        snprintf(hex, sizeof hex, "%%X%08X", st);
        st_jw_kstr(&w, "status", hex);
        st_jw_kbool(&w, "success", (st & 1) != 0);
    }
    st_jw_kbool(&w, "truncated", lc.truncated);
    st_jw_obj_end(&w);
}
