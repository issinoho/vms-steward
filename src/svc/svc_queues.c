/* svc_queues.c - batch and print queues, read-only (Phase 9, D17).

   GET api/v1/queues               every queue, as SHOW QUEUE
   GET api/v1/queues/{name}        one queue and its jobs, as SHOW QUEUE/ALL/FULL
   GET api/v1/jobs/{entry}         one job, as SHOW ENTRY/FULL
   POST api/v1/jobs/{entry}/hold, /release, DELETE api/v1/jobs/{entry}       (9b)
   POST api/v1/queues/{name}/stop, /start                                   (9b)

   $GETQUI runs under the persona and the queue manager judges it: a job the viewer
   may not read is listed with its entry and status only, "inaccessible", as SHOW
   QUEUE/ALL shows it at a terminal (probe_qui). */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_queue.h"

#define MAX_JOBS 10000

static void names_json(st_jw *w, const char *key, const char *list)
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

static void queue_json(st_jw *w, const st_queue *q)
{
    char status[400];
    st_jw_kstr(w, "name", q->name);
    st_jw_kstr(w, "kind", q->batch ? "batch" : "output");
    st_jw_kbool(w, "generic", q->generic);
    st_queue_status_names(q->status, status, sizeof status);
    names_json(w, "status", status);
    st_jw_kstr(w, "node", q->node);
    st_jw_kstr(w, "description", q->description);
    st_jw_kint(w, "job_limit", q->job_limit);
    st_jw_kint(w, "executing", q->executing);
    st_jw_kint(w, "pending", q->pending);
    st_jw_kint(w, "holding", q->holding);
    st_jw_kint(w, "timed", q->timed);
}

static void job_json(st_jw *w, const st_job *j)
{
    char status[300];
    st_jw_kint(w, "entry", j->entry);
    st_jw_kbool(w, "accessible", !(j->status & ST_JOB_INACCESSIBLE));
    st_jw_kstr(w, "name", j->name);
    st_jw_kstr(w, "username", j->username);
    st_job_status_names(j->status & ~ST_JOB_INACCESSIBLE, status, sizeof status);
    names_json(w, "status", status);
    st_jw_kstr(w, "queue", j->queue);
    if (j->submitted) st_jw_kint(w, "submitted", j->submitted);
}

static int queue_one(const st_queue *q, void *ctx)
{
    st_jw *w = ctx;
    st_jw_obj(w);
    queue_json(w, q);
    st_jw_obj_end(w);
    return 0;
}

void svc_queues(st_ctx *c)
{
    st_err e;
    st_jw w;
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_key(&w, "queues");
    st_jw_arr(&w);
    if (st_plat_queue_enum(queue_one, &w, &e)) {
        st_jw_arr_end(&w);
        st_jw_obj_end(&w);
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

typedef struct { st_jw *w; int n, truncated; } jobs_ctx;

static int job_one(const st_job *j, void *ctx)
{
    jobs_ctx *jc = ctx;
    if (jc->n >= MAX_JOBS) { jc->truncated = 1; return 1; }
    st_jw_obj(jc->w);
    job_json(jc->w, j);
    st_jw_obj_end(jc->w);
    jc->n++;
    return 0;
}

void svc_queue_get(st_ctx *c)
{
    static st_queue q;
    char name[ST_QUEUE_NAME_MAX + 1];
    jobs_ctx jc;
    st_err e;
    st_jw w;

    if (!st_valid_queue_name(c->args[0], name)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad queue name",
                        "1 to 31 characters from A-Z, 0-9, $ and _.", 0, NULL);
        return;
    }
    /* The jobs as the walk gives them, then the queue's own fields, filled by then:
       a JSON object's members have no order. */
    memset(&jc, 0, sizeof jc);
    st_resp_json(c->resp, 200, &w);
    jc.w = &w;
    st_jw_obj(&w);
    st_jw_key(&w, "jobs");
    st_jw_arr(&w);
    if (st_plat_queue_get(name, &q, job_one, &jc, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", jc.truncated);
    queue_json(&w, &q);
    st_jw_obj_end(&w);
}

void svc_job_get(st_ctx *c)
{
    static st_job_detail d;
    unsigned int entry;
    char uic[24];
    st_err e;
    st_jw w;
    int i;

    if (!st_parse_entry(c->args[0], &entry)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad entry number", "1 to 9 digits.", 0, NULL);
        return;
    }
    if (st_plat_job_get(entry, &d, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    job_json(&w, &d.j);
    if (d.after) st_jw_kint(&w, "after", d.after);
    st_jw_kint(&w, "priority", d.priority);
    st_jw_kstr(&w, "account", d.account);
    svc_uic_text(d.uic, uic);
    st_jw_kstr(&w, "uic", uic);
    st_jw_kstr(&w, "log", d.log);
    st_jw_key(&w, "files");
    st_jw_arr(&w);
    for (i = 0; i < d.nfiles; i++) st_jw_str(&w, d.files[i]);
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}

/* ---- changes (Phase 9b): $SNDJBC as the viewer; the queue manager decides ---- */

static int entry_arg(st_ctx *c, unsigned int *entry, char text[16])
{
    if (!st_parse_entry(c->args[0], entry)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad entry number", "1 to 9 digits.", 0, NULL);
        return -1;
    }
    snprintf(text, 16, "%u", *entry);
    return 0;
}

static void job_change(st_ctx *c, int op, const char *action, const char *done)
{
    static st_job_detail d;
    unsigned int entry;
    char text[16], target[96];   /* entry, "name" (39), username (12) */
    st_err e;
    st_jw w;

    if (entry_arg(c, &entry, text)) return;
    /* The job's name for the audit log, if the viewer may read it. */
    if (!st_plat_job_get(entry, &d, &e)) snprintf(target, sizeof target, "%s \"%s\" %s", text, d.j.name, d.j.username);
    else st_copy(target, sizeof target, text);
    if (st_plat_job_change(entry, op, &e)) {
        st_app_audit(c, c->session.username, action, target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, action, target, "ok", NULL);
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kint(&w, "entry", entry);
    st_jw_kstr(&w, "done", done);
    st_jw_obj_end(&w);
}

void svc_job_hold(st_ctx *c) { job_change(c, ST_JOB_HOLD, "job-hold", "held"); }
void svc_job_release(st_ctx *c) { job_change(c, ST_JOB_RELEASE, "job-release", "released"); }
void svc_job_delete(st_ctx *c) { job_change(c, ST_JOB_DELETE, "job-delete", "deleted"); }

static int no_job(const st_job *j, void *ctx) { (void) j; (void) ctx; return 1; }

static void queue_change(st_ctx *c, int op, const char *action)
{
    static st_queue q;
    char name[ST_QUEUE_NAME_MAX + 1], startup[8][32];
    int i, n;
    st_err e;
    st_jw w;

    if (!st_valid_queue_name(c->args[0], name)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad queue name",
                        "1 to 31 characters from A-Z, 0-9, $ and _.", 0, NULL);
        return;
    }
    /* Never the queues Steward's start-up uses: the pool is started at boot by a job
       submitted to SYS$BATCH (D17, the user's choice after OPCOM). */
    if (op == ST_QUEUE_STOP) {
        n = st_plat_startup_queues(startup, 8);
        for (i = 0; i < n; i++)
            if (!strcmp(startup[i], name)) {
                st_app_audit(c, c->session.username, action, name, "refused", "Steward's start-up queue");
                st_resp_problem(c->resp, 409, "startup-queue", "Steward's start-up queue",
                                "Steward does not stop SYS$BATCH or the queues it feeds: its pool is started there at boot. Use STOP/QUEUE at a terminal if you must.", 0, NULL);
                return;
            }
    }
    if (st_plat_queue_change(name, op, &e)) {
        st_app_audit(c, c->session.username, action, name, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, action, name, "ok", NULL);
    if (st_plat_queue_get(name, &q, no_job, NULL, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    queue_json(&w, &q);
    st_jw_obj_end(&w);
}

void svc_queue_stop(st_ctx *c) { queue_change(c, ST_QUEUE_STOP, "queue-stop"); }
void svc_queue_start(st_ctx *c) { queue_change(c, ST_QUEUE_START, "queue-start"); }

