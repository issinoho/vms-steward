/* svc_errlog.c - the error log, read-only (Phase 14, D23).

   GET api/v1/errorlog?days=        the events in ERRLOG.SYS over the last days (30 by
                                    default; 0 for all), oldest first, as ELV lists them
   GET api/v1/errorlog/{n}          one event, translated field by field
   GET api/v1/crashes               CLUE's listing of each crash, with its summary
   GET api/v1/crashes/{name}        one listing, its summary and its text
   GET api/v1/operator-log?stamps=  OPCOM's log, the newest version: its messages,
                                    without the hourly time stamps unless stamps=1
   GET api/v1/device-errors         each device with errors, and how many were looked at

   Changes (14b, D24), in-process under the persona, each audited:
   GET    api/v1/errorlog/files     ERRLOG.SYS and the logs renamed from it
   POST   api/v1/errorlog/new       start a new error log: rename ERRLOG.SYS to
                                    ERRLOG_<yyyymmdd>_<hhmm>.SYS; ERRFMT starts a new one
                                    at its next record
   DELETE api/v1/crashes/{name}     delete a crash listing
   POST   api/v1/crashes/purge      {"before": "yyyy-mm-dd"}: delete the listings of
                                    crashes before that day
   GET api/v1/errorlog and errorlog/{n} take ?file= for a renamed log.

   The error log through the D14 helper, which is the viewer, running ELV (st_errlog.c);
   ELV reports a viewer without access as "file not found" and success, so its message
   decides (NOTES.md). The listings and OPCOM's log are read in-process as the viewer.
   All three need SYSPRV or the SYSTEM group, as OpenVMS sets them (D10); the device
   counts are anyone's. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_errlog.h"
#include "st_buf.h"

#define MAX_EVENTS 100000
#define MAX_TEXT   (512 * 1024)   /* a crash listing: about 24 KB seen */
#define MAX_OPCOM  2000           /* the newest kept */

static int uint_query(st_ctx *c, const char *name, unsigned int hi, unsigned int *out)
{
    char raw[16], *end;
    unsigned long v;
    int got = svc_query(c, name, raw, sizeof raw);
    if (got <= 0) return got;
    v = strtoul(raw, &end, 10);
    if (!*raw || *end || v > hi) {
        char d[80];
        snprintf(d, sizeof d, "%s is a whole number from 0 to %u.", name, hi);
        st_resp_problem(c->resp, 400, "bad-request", "Bad query parameter", d, 0, NULL);
        return -1;
    }
    *out = (unsigned int) v;
    return 1;
}

/* The file is not there: found by name as the viewer, which needs no access to the
   file itself, so this is the truth (a refusal is PRV, NOTES.md). ERRLOG.SYS is
   missing after a new log is started, until ERRFMT's next record. */
static void not_found(st_ctx *c, const char *privs, const char *file, const char *vms)
{
    char d[480];
    (void) privs;
    snprintf(d, sizeof d, "%s%s%s does not exist.%s", vms, *vms ? ". " : "", file,
             strcmp(file, "ERRLOG.SYS") ? "" : " After a new error log is started, ERRFMT creates it at its next record.");
    st_resp_problem(c->resp, 404, "not-found", "Not found", d, 0, NULL);
}

/* ELV refused the file: OpenVMS's words, and what they may mean. */
static void elv_refusal(st_ctx *c, const char *privs, const char *file, const st_elv_parser *p)
{
    if (strstr(p->message, "-RMS-E-FNF")) { not_found(c, privs, file, p->message); return; }
    st_resp_problem(c->resp, 403, "no-privilege", "Not permitted by OpenVMS", p->message, 0, NULL);
}

/* ?file=: ERRLOG.SYS by default, or a renamed log. 0, or -1 having answered 400. */
static int file_query(st_ctx *c, char file[32])
{
    int got = svc_query(c, "file", file, 32);
    if (got < 0) return -1;
    if (!got || !file[0]) { strcpy(file, "ERRLOG.SYS"); return 0; }
    if (!st_valid_errlog_name(file)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad error log name",
                        "ERRLOG.SYS, or ERRLOG_<yyyymmdd>_<hhmm>.SYS.", 0, NULL);
        return -1;
    }
    return 0;
}

static void event_members(st_jw *w, const st_elv_event *ev)
{
    st_jw_kint(w, "number", ev->number);
    st_jw_kstr(w, "type", ev->type);
    st_jw_kstr(w, "time", ev->iso[0] ? ev->iso : ev->when);
    st_jw_kstr(w, "node", ev->node);
    st_jw_kstr(w, "class", ev->cls);
}

typedef struct { st_jw *w; int n, truncated; } list_ctx;

static int list_one(const st_elv_event *ev, void *ctx)
{
    list_ctx *lc = ctx;
    if (lc->n >= MAX_EVENTS) { lc->truncated = 1; return 1; }
    lc->n++;
    st_jw_obj(lc->w);
    event_members(lc->w, ev);
    st_jw_obj_end(lc->w);
    return 0;
}

void svc_errorlog(st_ctx *c)
{
    static st_elv_parser p;
    unsigned int days = 30;
    char privs[512], file[32];
    list_ctx lc;
    st_err e;
    st_jw w;

    if (uint_query(c, "days", 9999, &days) < 0) return;   /* DCL's delta time stops at 9999 days */
    if (file_query(c, file)) return;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kint(&w, "days", days);
    st_jw_kstr(&w, "file", file);
    st_jw_key(&w, "events");   /* oldest first */
    st_jw_arr(&w);
    memset(&lc, 0, sizeof lc);
    lc.w = &w;
    st_elv_init(&p, list_one, NULL, &lc);
    svc_session_privs(c, privs, sizeof privs);
    if (st_plat_errlog(privs, ST_ELV_LIST, days, file, &p, &e)) {
        if (e.kind == ST_E_NOTFOUND) not_found(c, privs, file, e.text);
        else st_app_error(c, &e);
        return;
    }
    if (st_elv_refused(&p)) { elv_refusal(c, privs, file, &p); return; }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", lc.truncated);
    st_jw_obj_end(&w);
}

typedef struct { st_jw *w; int events, fields; } entry_ctx;

static int entry_event(const st_elv_event *ev, void *ctx)
{
    entry_ctx *ec = ctx;
    if (ec->events++) return 0;   /* the one asked for */
    st_jw_key(ec->w, "event");
    st_jw_obj(ec->w);
    event_members(ec->w, ev);
    st_jw_obj_end(ec->w);
    st_jw_key(ec->w, "fields");
    st_jw_arr(ec->w);
    return 0;
}

static int entry_field(const st_elv_field *f, void *ctx)
{
    entry_ctx *ec = ctx;
    if (!ec->events || ec->fields >= 2000) return 0;
    ec->fields++;
    st_jw_obj(ec->w);
    if (f->text) {
        st_jw_kstr(ec->w, "text", f->description);
    } else {
        st_jw_kstr(ec->w, "description", f->description);
        if (f->range[0]) st_jw_kstr(ec->w, "range", f->range);
        st_jw_kstr(ec->w, "value", f->value);
        if (f->translated[0]) st_jw_kstr(ec->w, "translated", f->translated);
        if (f->indent) st_jw_kint(ec->w, "indent", f->indent);
    }
    if (f->group) st_jw_kbool(ec->w, "group", 1);
    st_jw_obj_end(ec->w);
    return 0;
}

void svc_errorlog_event(st_ctx *c)
{
    static st_elv_parser p;
    unsigned long n;
    char *end, privs[512], file[32];
    entry_ctx ec;
    st_err e;
    st_jw w;

    n = strtoul(c->args[0], &end, 10);
    if (!c->args[0][0] || *end || n == 0 || n > 0x7FFFFFFFul || strlen(c->args[0]) > 10) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad event number", NULL, 0, NULL);
        return;
    }
    if (file_query(c, file)) return;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    memset(&ec, 0, sizeof ec);
    ec.w = &w;
    st_elv_init(&p, entry_event, entry_field, &ec);
    svc_session_privs(c, privs, sizeof privs);
    if (st_plat_errlog(privs, ST_ELV_ENTRY, (unsigned int) n, file, &p, &e)) {
        if (e.kind == ST_E_NOTFOUND) not_found(c, privs, file, e.text);
        else st_app_error(c, &e);
        return;
    }
    if (st_elv_refused(&p)) { elv_refusal(c, privs, file, &p); return; }
    if (!ec.events) {
        st_resp_problem(c->resp, 404, "not-found", "Not found", "No such event in the error log.", 0, NULL);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

/* ---- crashes ---- */

static void summary_members(st_jw *w, const st_clue_summary *s)
{
    char iso[20];
    const char *t = st_clue_get(s, "Crash Time");
    st_vms_time_iso(t, iso);
    st_jw_kstr(w, "time", iso[0] ? iso : t);
    st_jw_kstr(w, "bugcheck", st_clue_get(s, "Bugcheck Type"));
    st_jw_kstr(w, "process", st_clue_get(s, "Current Process"));
    st_jw_kstr(w, "image", st_clue_get(s, "Current Image"));
    st_jw_kstr(w, "pc", st_clue_get(s, "Failing PC"));
    st_jw_kstr(w, "module", st_clue_get(s, "Module"));
    st_jw_kstr(w, "uptime", st_clue_get(s, "System Uptime"));
}

typedef struct { st_jw *w; int n; } crash_ctx;

static int crash_one(const char *name, const st_clue_summary *s, void *ctx)
{
    crash_ctx *cc = ctx;
    if (cc->n >= 5000) return 1;
    cc->n++;
    st_jw_obj(cc->w);
    st_jw_kstr(cc->w, "name", name);
    summary_members(cc->w, s);
    st_jw_obj_end(cc->w);
    return 0;
}

void svc_crashes(st_ctx *c)
{
    crash_ctx cc;
    st_err e;
    st_jw w;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "crashes");   /* in directory order: by node, then date as ddmmyy */
    st_jw_arr(&w);
    memset(&cc, 0, sizeof cc);
    cc.w = &w;
    if (st_plat_crashes(crash_one, &cc, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

typedef struct { st_buf text; st_clue_summary s; int over; } text_ctx;

static int text_line(const char *line, size_t len, void *ctx)
{
    text_ctx *tc = ctx;
    st_clue_line(&tc->s, line, len);
    if (tc->text.len + len + 1 > MAX_TEXT) { tc->over = 1; return 1; }
    st_buf_append(&tc->text, line, len);
    st_buf_append(&tc->text, "\n", 1);
    return 0;
}

void svc_crash_get(st_ctx *c)
{
    static text_ctx tc;
    st_err e;
    st_jw w;
    int i;
    if (!st_valid_clue_name(c->args[0])) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad listing name",
                        "CLUE$<node>_<ddmmyy>_<hhmm>.LIS, in capitals.", 0, NULL);
        return;
    }
    st_buf_init(&tc.text, 0);
    st_clue_init(&tc.s);
    tc.over = 0;
    if (st_plat_crash_text(c->args[0], text_line, &tc, &e)) { st_buf_free(&tc.text); st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "name", c->args[0]);
    summary_members(&w, &tc.s);
    st_jw_key(&w, "summary");   /* every "Name: value" of the first page, in order */
    st_jw_arr(&w);
    for (i = 0; i < tc.s.nitems; i++) {
        st_jw_obj(&w);
        st_jw_kstr(&w, "key", tc.s.items[i].key);
        st_jw_kstr(&w, "value", tc.s.items[i].value);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    st_buf_append(&tc.text, "", 1);   /* NUL-terminated for the writer */
    st_jw_kstr(&w, "text", st_buf_ok(&tc.text) ? tc.text.data : "");
    st_jw_kbool(&w, "truncated", tc.over);
    st_jw_obj_end(&w);
    st_buf_free(&tc.text);
}

/* ---- OPCOM's log ---- */

typedef struct { st_opcom_msg *ring; int n, next, stamps; long total; } opcom_ctx;

static int opcom_one(const st_opcom_msg *m, void *ctx)
{
    opcom_ctx *oc = ctx;
    if (m->stamp && !oc->stamps) return 0;
    oc->total++;
    oc->ring[oc->next] = *m;
    oc->next = (oc->next + 1) % MAX_OPCOM;
    if (oc->n < MAX_OPCOM) oc->n++;
    return 0;
}

void svc_operator_log(st_ctx *c)
{
    static st_opcom_msg ring[MAX_OPCOM];
    static st_opcom_parser p;
    unsigned int stamps = 0;
    char file[96];
    opcom_ctx oc;
    st_err e;
    st_jw w;
    int i;

    if (uint_query(c, "stamps", 1, &stamps) < 0) return;
    memset(&oc, 0, sizeof oc);
    oc.ring = ring;
    oc.stamps = (int) stamps;
    st_opcom_init(&p, opcom_one, &oc);
    if (st_plat_opcom(&p, file, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "file", file);
    st_jw_key(&w, "messages");   /* newest first */
    st_jw_arr(&w);
    for (i = 0; i < oc.n; i++) {
        const st_opcom_msg *m = &ring[(oc.next - 1 - i + 2 * MAX_OPCOM) % MAX_OPCOM];
        st_jw_obj(&w);
        st_jw_kstr(&w, "time", m->iso[0] ? m->iso : m->when);
        if (m->from[0]) st_jw_kstr(&w, "from", m->from);
        if (m->node[0]) st_jw_kstr(&w, "node", m->node);
        st_jw_kstr(&w, "text", m->text);
        if (m->stamp) st_jw_kbool(&w, "stamp", 1);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", oc.total > oc.n);
    st_jw_obj_end(&w);
}

/* ---- device errors ---- */

typedef struct { st_jw *w; int n; } dev_ctx;

static int dev_one(const st_dev_errors *d, void *ctx)
{
    dev_ctx *dc = ctx;
    if (dc->n >= 5000) return 1;
    dc->n++;
    st_jw_obj(dc->w);
    st_jw_kstr(dc->w, "device", d->device);
    st_jw_kint(dc->w, "errors", d->errors);
    st_jw_obj_end(dc->w);
    return 0;
}

void svc_device_errors(st_ctx *c)
{
    dev_ctx dc;
    st_err e;
    st_jw w;
    int scanned = 0;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "devices");
    st_jw_arr(&w);
    memset(&dc, 0, sizeof dc);
    dc.w = &w;
    if (st_plat_device_errors(dev_one, &dc, &scanned, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_kint(&w, "scanned", scanned);
    st_jw_obj_end(&w);
}

/* ---- changes (14b, D24) ---- */

typedef struct { st_jw *w; int n; } files_ctx;

static int file_one(const char *name, unsigned int blocks, const char *created, void *ctx)
{
    files_ctx *fc = ctx;
    if (fc->n >= 1000) return 1;
    fc->n++;
    st_jw_obj(fc->w);
    st_jw_kstr(fc->w, "name", name);
    st_jw_kint(fc->w, "blocks", blocks);
    st_jw_kstr(fc->w, "created", created);
    st_jw_obj_end(fc->w);
    return 0;
}

void svc_errorlog_files(st_ctx *c)
{
    files_ctx fc;
    st_err e;
    st_jw w;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "files");   /* as the directory lists them */
    st_jw_arr(&w);
    memset(&fc, 0, sizeof fc);
    fc.w = &w;
    if (st_plat_errlog_files(file_one, &fc, &e)) {
        char privs[512];
        svc_session_privs(c, privs, sizeof privs);
        if (e.kind == ST_E_NOTFOUND) { not_found(c, privs, "ERRLOG.SYS", e.text); return; }
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

void svc_errorlog_new(st_ctx *c)
{
    char newname[32], privs[512];
    st_err e;
    st_jw w;
    if (st_plat_errlog_rename(newname, &e)) {
        st_app_audit(c, c->session.username, "errorlog-new", "ERRLOG.SYS", "failed", e.text);
        svc_session_privs(c, privs, sizeof privs);
        if (e.kind == ST_E_NOTFOUND) { not_found(c, privs, "ERRLOG.SYS", e.text); return; }
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "errorlog-new", "ERRLOG.SYS", "ok", newname);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "renamed_to", newname);
    st_jw_obj_end(&w);
}

void svc_crash_delete(st_ctx *c)
{
    st_err e;
    if (!st_valid_clue_name(c->args[0])) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad listing name",
                        "CLUE$<node>_<ddmmyy>_<hhmm>.LIS, in capitals.", 0, NULL);
        return;
    }
    if (st_plat_crash_delete(c->args[0], &e)) {
        st_app_audit(c, c->session.username, "crash-delete", c->args[0], "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "crash-delete", c->args[0], "ok", NULL);
    c->resp->status = 204;
}

#define MAX_PURGE 5000
typedef struct { char before[11]; char (*names)[40]; int n; } purge_ctx;

static int purge_pick(const char *name, const st_clue_summary *s, void *ctx)
{
    purge_ctx *pc = ctx;
    char iso[20];
    st_vms_time_iso(st_clue_get(s, "Crash Time"), iso);
    /* Before the day: its date sorts before it. A listing whose time cannot be read
       is never taken. */
    if (iso[0] && strncmp(iso, pc->before, 10) < 0 && pc->n < MAX_PURGE && strlen(name) < 40)
        strcpy(pc->names[pc->n++], name);
    return 0;
}

static int valid_day(const char *s)
{
    int i;
    if (strlen(s) != 10 || s[4] != '-' || s[7] != '-') return 0;
    for (i = 0; i < 10; i++) if (i != 4 && i != 7 && (s[i] < '0' || s[i] > '9')) return 0;
    return (s[5] - '0') * 10 + (s[6] - '0') >= 1 && (s[5] - '0') * 10 + (s[6] - '0') <= 12 &&
           (s[8] - '0') * 10 + (s[9] - '0') >= 1 && (s[8] - '0') * 10 + (s[9] - '0') <= 31;
}

void svc_crash_purge(st_ctx *c)
{
    static char names[MAX_PURGE][40];
    purge_ctx pc;
    st_jdoc doc;
    const char *before;
    st_err e;
    st_jw w;
    int i, deleted = 0;

    if (st_app_body(c, &doc)) return;
    before = doc.root && doc.root->type == ST_JOBJ ? st_json_get_str(doc.root, "before") : NULL;
    if (!before || !valid_day(before)) {
        st_json_free(&doc);
        st_resp_problem(c->resp, 422, "invalid-value", "Invalid value", "before is a day, yyyy-mm-dd.", 0, NULL);
        return;
    }
    memset(&pc, 0, sizeof pc);
    memcpy(pc.before, before, 10);
    st_json_free(&doc);
    pc.names = names;
    if (st_plat_crashes(purge_pick, &pc, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "before", pc.before);
    st_jw_key(&w, "deleted");
    st_jw_arr(&w);
    for (i = 0; i < pc.n; i++) {
        if (st_plat_crash_delete(names[i], &e)) {
            st_app_audit(c, c->session.username, "crash-delete", names[i], "failed", e.text);
            continue;   /* counted in "failed"; the audit log has why */
        }
        st_app_audit(c, c->session.username, "crash-delete", names[i], "ok", "purge");
        st_jw_str(&w, names[i]);
        deleted++;
    }
    st_jw_arr_end(&w);
    st_jw_kint(&w, "failed", pc.n - deleted);
    st_jw_obj_end(&w);
}
