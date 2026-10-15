/* svc_processes.c - processes, read-only (Phase 8, D16).

   GET api/v1/processes?filter=     the processes the viewer may see, as SHOW SYSTEM
   GET api/v1/processes/{pid}       one, as SHOW PROCESS/ALL
   DELETE api/v1/processes/{pid}    stop it, as STOP/ID (Phase 8b)

   $GETJPI runs under the persona, so OpenVMS decides which processes are shown: the
   viewer's own, their group's with GROUP, everyone's with WORLD (probe_jpi). The
   process serving the request is never shown: it would carry the viewer's name. */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_proc.h"

#define MAX_PROCS 4000

static void pid_text(unsigned int pid, char out[9]) { snprintf(out, 9, "%08X", pid); }

static void proc_json(st_jw *w, const st_proc *p)
{
    char pid[9], uic[24];
    pid_text(p->pid, pid);
    svc_uic_text(p->uic, uic);
    st_jw_kstr(w, "pid", pid);
    st_jw_kstr(w, "name", p->name);
    st_jw_kstr(w, "username", p->username);
    st_jw_kstr(w, "uic", uic);
    st_jw_kstr(w, "state", st_proc_state_name(p->state));
    st_jw_kint(w, "priority", p->pri);
    st_jw_kint(w, "base_priority", p->prib);
    st_jw_kstr(w, "kind", st_proc_kind(p->mode, p->subprocess));
    st_jw_kstr(w, "terminal", p->terminal);
    st_jw_kstr(w, "image", p->image);
    st_jw_kint(w, "cpu_ms", (long long) p->cputim * 10);
    st_jw_kint(w, "direct_io", p->dirio);
    st_jw_kint(w, "buffered_io", p->bufio);
    st_jw_kint(w, "page_faults", p->pageflts);
    st_jw_kint(w, "login", p->login);
    st_jw_kbool(w, "system", (p->uic >> 16) <= st_plat_max_sys_group());
}

typedef struct { st_jw *w; const char *filter; int n, truncated; } list_ctx;

static int list_one(const st_proc *p, void *ctx)
{
    list_ctx *lc = ctx;
    if (*lc->filter && !st_filter_match(lc->filter, p->name, p->username) &&
        !st_filter_match(lc->filter, p->username, NULL))
        return 0;
    if (lc->n >= MAX_PROCS) { lc->truncated = 1; return 1; }
    st_jw_obj(lc->w);
    proc_json(lc->w, p);
    st_jw_obj_end(lc->w);
    lc->n++;
    return 0;
}

void svc_processes(st_ctx *c)
{
    char raw[64], filter[ST_IDENT_MAX + 1] = "";
    list_ctx lc;
    st_err e;
    st_jw w;
    int got;

    if ((got = svc_query(c, "filter", raw, sizeof raw)) < 0) return;
    if (got && *raw && !st_valid_filter(raw, filter)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad filter",
                        "Up to 31 printable characters; * and % are wildcards.", 0, NULL);
        return;
    }
    memset(&lc, 0, sizeof lc);
    lc.filter = filter;
    st_resp_json(c->resp, 200, &w);
    lc.w = &w;
    st_jw_obj(&w);
    st_jw_key(&w, "processes");
    st_jw_arr(&w);
    if (st_plat_proc_enum(list_one, &lc, &e)) {
        st_jw_arr_end(&w);
        st_jw_obj_end(&w);
        st_app_error(c, &e);
        return;
    }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", lc.truncated);
    st_jw_obj_end(&w);
}

void svc_process_get(st_ctx *c)
{
    static const char *const quotas[ST_PQ_COUNT] = { "astlm", "biolm", "diolm", "fillm", "prclm",
        "tqelm", "enqlm", "bytlm", "pgflquota" };
    static st_proc_detail d;
    unsigned int pid;
    char text[9];
    st_err e;
    st_jw w;
    int i;

    if (!st_parse_pid(c->args[0], &pid)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad PID",
                        "8 hexadecimal digits, as SHOW SYSTEM lists it.", 0, NULL);
        return;
    }
    if (st_plat_proc_get(pid, &d, &e)) { st_app_error(c, &e); return; }
    if (d.p.pid != pid) {   /* never another process than the one asked for */
        st_resp_problem(c->resp, 404, "not-found", "Not found", NULL, 0, NULL);
        return;
    }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    proc_json(&w, &d.p);
    if (d.owner) { pid_text(d.owner, text); st_jw_kstr(&w, "owner", text); }
    pid_text(d.master, text);
    st_jw_kstr(&w, "master", text);
    st_jw_kint(&w, "subprocesses", d.subprocesses);
    st_jw_kint(&w, "working_set_size", d.wssize);
    st_jw_kint(&w, "working_set_pages", d.wspages);
    svc_privs_json(&w, "current_privileges", d.priv_cur);
    svc_privs_json(&w, "authorized_privileges", d.priv_auth);
    st_jw_key(&w, "rights");
    st_jw_arr(&w);
    for (i = 0; i < d.nids; i++) st_jw_str(&w, d.ids[i]);
    st_jw_arr_end(&w);
    st_jw_key(&w, "quotas");
    st_jw_obj(&w);
    for (i = 0; i < ST_PQ_COUNT; i++) {
        st_jw_key(&w, quotas[i]);
        st_jw_obj(&w);
        st_jw_kint(&w, "limit", d.quota[i]);
        st_jw_kint(&w, "left", d.left[i]);
        st_jw_obj_end(&w);
    }
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}

static int st_eq_nocase(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = (*a >= 'a' && *a <= 'z') ? (char) (*a - 32) : *a, y = (*b >= 'a' && *b <= 'z') ? (char) (*b - 32) : *b;
        if (x != y) return 0;
    }
    return *a == *b;
}

/* DELETE api/v1/processes/{pid}: stop it, as STOP/ID. OpenVMS decides who may; Steward
   refuses its own pool (the service account's processes), whoever asks: stopping it
   from the browser would cut the browser off. 202: $DELPRC is asynchronous. */
void svc_process_stop(st_ctx *c)
{
    static st_proc_detail d;
    unsigned int pid;
    char text[9], target[64], image[64];
    st_err e;
    st_jw w;

    if (!st_parse_pid(c->args[0], &pid)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad PID",
                        "8 hexadecimal digits, as SHOW SYSTEM lists it.", 0, NULL);
        return;
    }
    pid_text(pid, text);
    /* What it is, as the viewer sees it: NOPRIV or NONEXPR end it here. */
    if (st_plat_proc_get(pid, &d, &e)) {
        st_app_audit(c, c->session.username, "process-stop", text, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    if (d.p.pid != pid) {   /* never another process than the one asked for */
        st_resp_problem(c->resp, 404, "not-found", "Not found", NULL, 0, NULL);
        return;
    }
    /* The name in quotes: its owner chose it, and it may hold spaces. */
    snprintf(target, sizeof target, "%s \"%s\" %s", text, d.p.name, d.p.username);
    /* Steward's own: the service account's processes, and any running Steward's image,
       since a worker busy with a request reports the requester's username. */
    st_proc_image_name(d.p.image, image, sizeof image);
    if (st_eq_nocase(d.p.username, st_plat_service_account()) ||
        (*st_plat_service_image() && !strcmp(image, st_plat_service_image()))) {
        st_app_audit(c, c->session.username, "process-stop", target, "refused", "Steward's own process");
        st_resp_problem(c->resp, 409, "steward-process", "Steward's own process",
                        "Steward does not stop its own processes: that would cut off this page. Use STEWARD$CONTROL at a terminal.", 0, NULL);
        return;
    }
    /* A system process (UIC group up to MAXSYSGROUP: OPCOM, JOB_CONTROL, the ACPs),
       whatever OpenVMS would allow: the user's decision after OPCOM was stopped in
       the 8b browser check. At a terminal it stays possible. */
    if ((d.p.uic >> 16) <= st_plat_max_sys_group()) {
        st_app_audit(c, c->session.username, "process-stop", target, "refused", "system process");
        st_resp_problem(c->resp, 409, "system-process", "System process",
                        "Steward does not stop system processes (UIC group up to MAXSYSGROUP). Use STOP/ID at a terminal if you must.", 0, NULL);
        return;
    }
    if (st_plat_proc_stop(pid, &e)) {
        st_app_audit(c, c->session.username, "process-stop", target, "failed", e.text);
        st_app_error(c, &e);
        return;
    }
    st_app_audit(c, c->session.username, "process-stop", target, "ok", NULL);
    st_resp_json(c->resp, 202, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "pid", text);
    st_jw_kstr(&w, "name", d.p.name);
    st_jw_kstr(&w, "username", d.p.username);
    st_jw_kbool(&w, "stopping", 1);
    st_jw_obj_end(&w);
}

