/* svc_access.c - access history: GET api/v1/access (Phase 6, D13).

   Who reached the system, when, from where and how, merged by the platform from the
   system's own records, read under the viewer's persona. A source OpenVMS will not let
   the viewer read is reported as refused, and the others are still shown. Filters and
   the order are applied here: newest first. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

#define MAX_EVENTS 4000           /* gathered per request; past this, "truncated" */
#define LIMIT_DEFAULT 500
#define LIMIT_MAX 2000

static const char *const kind_names[] = { "session", "failure", "breakin", "connected" };
static const char *const source_names[ST_SRC_COUNT] = { "accounting", "audit", "ssh", "steward", "live" };

typedef struct {
    st_access_event *ev;
    int              n, truncated;
    char             user[32];      /* filter: wildcard or substring, upper case */
    char             route[32];     /* filter: exact, case-insensitive */
    int              kind;          /* filter: -1 any */
} collect;

static int ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x = (char) (x - 32);
        if (y >= 'a' && y <= 'z') y = (char) (y - 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

static int take(const st_access_event *e, void *ctx)
{
    collect *c = ctx;
    if (*c->user && !st_filter_match(c->user, e->user, NULL)) return 0;
    if (*c->route && !ieq(c->route, e->route)) return 0;
    if (c->kind >= 0 && e->kind != c->kind) return 0;
    if (c->n == MAX_EVENTS) { c->truncated = 1; return 1; }
    c->ev[c->n++] = *e;
    return 0;
}

static int newest_first(const void *a, const void *b)
{
    long long x = ((const st_access_event *) a)->start, y = ((const st_access_event *) b)->start;
    return x < y ? 1 : x > y ? -1 : 0;
}

static int time_param(st_ctx *c, const char *name, long long *out)
{
    char raw[24], *end;
    long long v;
    int got = svc_query(c, name, raw, sizeof raw);
    if (got < 0) return -1;
    if (!got) return 0;
    v = strtoll(raw, &end, 10);
    if (!*raw || *end || v < 0 || v > 253402300799LL) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad time", "since and until are seconds since 1970.", 0, NULL);
        return -1;
    }
    *out = v;
    return 0;
}

/* GET api/v1/access?since=&until=&user=&route=&outcome=session|failure|breakin|connected&limit= */
void svc_access(st_ctx *c)
{
    static st_access_event events[MAX_EVENTS];
    unsigned int cond[ST_SRC_COUNT];
    char text[ST_SRC_COUNT][96], raw[64];
    int partial[ST_SRC_COUNT];
    long long until = st_plat_time(), since = until - 86400;
    int limit = LIMIT_DEFAULT, i, got;
    collect col;
    st_err e;
    st_jw w;

    memset(&col, 0, sizeof col);
    col.ev = events;
    col.kind = -1;
    if (time_param(c, "since", &since) || time_param(c, "until", &until)) return;
    if (since > until) { st_resp_problem(c->resp, 400, "bad-request", "since is after until", NULL, 0, NULL); return; }
    if ((got = svc_query(c, "user", raw, sizeof raw)) < 0) return;
    if (got && !st_valid_filter(raw, col.user)) {
        st_resp_problem(c->resp, 400, "bad-request", "Bad user filter", "Up to 31 printable characters; * and % are wildcards.", 0, NULL);
        return;
    }
    if ((got = svc_query(c, "route", raw, sizeof raw)) < 0) return;
    if (got && !st_valid_filter(raw, col.route)) { st_resp_problem(c->resp, 400, "bad-request", "Bad route", NULL, 0, NULL); return; }
    if ((got = svc_query(c, "outcome", raw, sizeof raw)) < 0) return;
    if (got) {
        for (i = 0; i < 4 && strcmp(raw, kind_names[i]); i++) ;
        if (i == 4) {
            st_resp_problem(c->resp, 400, "bad-request", "Bad outcome", "session, failure, breakin or connected.", 0, NULL);
            return;
        }
        col.kind = i;
    }
    if ((got = svc_query(c, "limit", raw, sizeof raw)) < 0) return;
    if (got) {
        char *end;
        long n = strtol(raw, &end, 10);
        if (!*raw || *end || n < 1 || n > LIMIT_MAX) {
            st_resp_problem(c->resp, 400, "bad-request", "Bad limit", "limit is 1 to 2000.", 0, NULL);
            return;
        }
        limit = (int) n;
    }

    if (st_plat_access(since, until, take, &col, cond, text, partial, &e)) { st_app_error(c, &e); return; }
    qsort(events, (size_t) col.n, sizeof events[0], newest_first);

    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kint(&w, "since", since);
    st_jw_kint(&w, "until", until);
    st_jw_key(&w, "sources");
    st_jw_obj(&w);
    for (i = 0; i < ST_SRC_COUNT; i++) {
        st_jw_key(&w, source_names[i]);
        st_jw_obj(&w);
        st_jw_kbool(&w, "read", cond[i] == 0);
        if (cond[i] == 0 && partial[i]) st_jw_kbool(&w, "complete", 0);
        if (cond[i]) {
            char hex[16];
            snprintf(hex, sizeof hex, "%%X%08X", cond[i]);
            st_jw_kstr(&w, "vms_status", hex);
            st_jw_kstr(&w, "vms_message", text[i]);
        }
        st_jw_obj_end(&w);
    }
    st_jw_obj_end(&w);
    st_jw_key(&w, "events");
    st_jw_arr(&w);
    for (i = 0; i < col.n && i < limit; i++) {
        const st_access_event *a = &events[i];
        st_jw_obj(&w);
        st_jw_kint(&w, "start", a->start);
        st_jw_key(&w, "end");
        if (a->end > 0) st_jw_int(&w, a->end); else st_jw_null(&w);
        st_jw_kstr(&w, "kind", kind_names[a->kind & 3]);
        st_jw_kstr(&w, "source", source_names[a->source < ST_SRC_COUNT ? a->source : 0]);
        st_jw_kstr(&w, "user", a->user);
        st_jw_kstr(&w, "route", a->route);
        st_jw_kstr(&w, "from", a->from);
        st_jw_kstr(&w, "terminal", a->terminal);
        st_jw_kstr(&w, "detail", a->detail);
        if (a->pid) {
            char pid[12];
            snprintf(pid, sizeof pid, "%08X", a->pid);
            st_jw_kstr(&w, "pid", pid);
        }
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    st_jw_kbool(&w, "truncated", col.truncated || col.n > limit);
    st_jw_obj_end(&w);
}
