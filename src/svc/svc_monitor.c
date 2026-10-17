/* svc_monitor.c - monitoring, read-only (Phase 13, D21, D22).

   GET api/v1/monitor    one reading of the counters MONITOR shows, and the processes
                         the viewer may see with theirs
   GET api/v1/monitor/history?minutes=&points=
                         readings from the recording (D22) spread over the last
                         minutes, at most points of them: the same counters, no
                         processes

   Raw counters, as OpenVMS keeps them from boot, and when they were read: no rates
   and no state here, so any pool process can answer, and a poll holds none for an
   interval (as svc_system leaves the CPU share to the browser). The page works out
   rates from consecutive readings and keeps the history (D21). $GETRMI needs no
   privilege; the processes are those $GETJPI shows the persona (Phase 8).

   The recording holds every interval's reading for a week (steward -r). Counters
   being cumulative, any two readings give the exact average between them, so a range
   is answered with readings a whole number of intervals apart and the page's rates.js
   does the rest unchanged. Read under the persona through the service's channel
   (st_platform.h): it holds only what $GETRMI gives anyone (D10). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"
#include "st_proc.h"

#define MAX_PROCS 4000
#define MAX_POINTS 1000
#define DEFAULT_MINUTES 360
#define DEFAULT_POINTS 300

static const char *const mode_keys[ST_MON_MODES] = {
    "interrupt", "mp_synch", "kernel", "executive", "supervisor", "user", "idle" };
/* As MONITOR STATES and SHOW SYSTEM name them. */
static const char *const state_keys[ST_MON_STATES] = {
    "CUR", "COM", "COMO", "LEF", "LEFO", "HIB", "HIBO", "SUSP", "SUSPO", "PFW", "MWAIT",
    "CEF", "COLPG", "FPG" };
static const char *const counter_keys[ST_MON_COUNTERS] = {
    "page_faults", "page_read_io", "page_write_io", "inswaps", "direct_io", "buffered_io",
    "mailbox_reads", "mailbox_writes" };

typedef struct { st_jw *w; int n, truncated; } mon_ctx;

static int one_proc(const st_proc *p, void *ctx)
{
    mon_ctx *mc = ctx;
    char pid[9];
    if (mc->n >= MAX_PROCS) { mc->truncated = 1; return 1; }
    mc->n++;
    snprintf(pid, sizeof pid, "%08X", p->pid);
    st_jw_obj(mc->w);
    st_jw_kstr(mc->w, "pid", pid);
    st_jw_kstr(mc->w, "name", p->name);
    st_jw_kstr(mc->w, "username", p->username);
    st_jw_kstr(mc->w, "state", st_proc_state_name(p->state));
    st_jw_kint(mc->w, "cpu_ms", (long long) p->cputim * 10);
    st_jw_kint(mc->w, "direct_io", p->dirio);
    st_jw_kint(mc->w, "buffered_io", p->bufio);
    st_jw_kint(mc->w, "page_faults", p->pageflts);
    st_jw_obj_end(mc->w);
    return 0;
}

/* The reading's members, into an object already open. */
static void reading(st_jw *w, const st_monitor *m)
{
    int i;
    st_jw_kint(w, "sampled_at_ms", m->sampled_at_ms);
    st_jw_kint(w, "cpus", m->cpus);
    st_jw_key(w, "modes");   /* ticks summed over CPUs, 100 a second a CPU */
    st_jw_obj(w);
    for (i = 0; i < ST_MON_MODES; i++) st_jw_kint(w, mode_keys[i], m->modes[i]);
    st_jw_obj_end(w);
    st_jw_key(w, "states");
    st_jw_obj(w);
    for (i = 0; i < ST_MON_STATES; i++) st_jw_kint(w, state_keys[i], m->states[i]);
    st_jw_obj_end(w);
    st_jw_kint(w, "processes", m->processes);
    st_jw_key(w, "memory");
    st_jw_obj(w);
    st_jw_kint(w, "total", (long long) m->mem_total);
    st_jw_kint(w, "free", (long long) m->mem_free);
    st_jw_kint(w, "modified", (long long) m->mem_modified);
    st_jw_obj_end(w);
    st_jw_key(w, "counters");   /* since boot; they wrap at 2^32 */
    st_jw_obj(w);
    for (i = 0; i < ST_MON_COUNTERS; i++) st_jw_kint(w, counter_keys[i], m->counters[i]);
    st_jw_obj_end(w);
    st_jw_key(w, "disks");
    st_jw_arr(w);
    for (i = 0; i < m->ndisks; i++) {
        st_jw_obj(w);
        st_jw_kstr(w, "device", m->disks[i].device);
        st_jw_kint(w, "operations", m->disks[i].operations);
        st_jw_obj_end(w);
    }
    st_jw_arr_end(w);
}

void svc_monitor(st_ctx *c)
{
    static st_monitor m;   /* ~1 KB with the disks: not on the stack */
    mon_ctx mc;
    st_err e;
    st_jw w;

    if (st_plat_monitor(&m, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    reading(&w, &m);

    memset(&mc, 0, sizeof mc);
    mc.w = &w;
    st_jw_key(&w, "visible");   /* the processes you may see (Phase 8) */
    st_jw_arr(&w);
    if (st_plat_proc_enum(one_proc, &mc, &e)) { st_app_error(c, &e); return; }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", mc.truncated);
    st_jw_obj_end(&w);
}

static int uint_param(st_ctx *c, const char *name, unsigned int lo, unsigned int hi, unsigned int *out)
{
    char raw[16], *end;
    unsigned long v;
    int got = svc_query(c, name, raw, sizeof raw);
    if (got <= 0) return got;
    v = strtoul(raw, &end, 10);
    if (!*raw || *end || v < lo || v > hi) {
        char d[96];
        snprintf(d, sizeof d, "%s is a whole number from %u to %u.", name, lo, hi);
        st_resp_problem(c->resp, 400, "bad-request", "Bad query parameter", d, 0, NULL);
        return -1;
    }
    *out = (unsigned int) v;
    return 0;
}

void svc_monitor_history(st_ctx *c)
{
    static unsigned char rec[ST_MREC_SIZE];
    static st_mrec_point pts[MAX_POINTS];
    static st_monitor m;
    unsigned int minutes = DEFAULT_MINUTES, points = DEFAULT_POINTS, step = 0, slot;
    st_mrec_header h;
    int n = 0, i, got, recording;
    st_err e;
    st_jw w;

    if (uint_param(c, "minutes", 1, 366 * 1440, &minutes) < 0) return;
    if (uint_param(c, "points", 2, MAX_POINTS, &points) < 0) return;
    if ((got = st_plat_history_get(0, rec, &e)) < 0) { st_app_error(c, &e); return; }
    recording = got == 1 && !st_mrec_decode_header(rec, ST_MREC_SIZE, &h);
    if (recording) n = st_mrec_plan(st_plat_now_ms(), minutes, points, &h, pts, MAX_POINTS, &step);

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kbool(&w, "recording", recording);
    if (recording) {
        st_jw_kint(&w, "interval_secs", h.interval_secs);
        st_jw_kint(&w, "kept_secs", (long long) h.interval_secs * h.slots);
        st_jw_kint(&w, "started_ms", h.started_ms);
        st_jw_kint(&w, "updated_ms", h.updated_ms);
        st_jw_kint(&w, "step_secs", step);
    }
    st_jw_key(&w, "readings");   /* oldest first; a missing one is simply not there */
    st_jw_arr(&w);
    for (i = 0; i < n; i++) {
        got = st_plat_history_get(pts[i].slot, rec, &e);
        if (got < 0) { st_app_error(c, &e); return; }
        if (!got || st_mrec_decode(rec, ST_MREC_SIZE, &m, &slot) || slot != pts[i].slot ||
            !st_mrec_matches(m.sampled_at_ms, pts[i].want_ms, h.interval_secs))
            continue;   /* not written, or left from an earlier lap */
        st_jw_obj(&w);
        reading(&w, &m);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);
}
