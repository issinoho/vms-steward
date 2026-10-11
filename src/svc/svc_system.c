/* svc_system.c - the system at a glance: GET api/v1/system, the dashboard's data.

   Read under the caller's persona like everything else (D2). The figures come from
   the system services vms-fastfetch uses (st_platform.h). CPU usage is not sampled
   here, which would hold a pool process for the interval: the response carries the
   idle-tick counter and when it was read, and the browser takes the busy share
   between two polls. */
#include <stdio.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

static void kull(st_jw *w, const char *key, unsigned long long v)
{
    st_jw_kint(w, key, (long long) v);
}

void svc_system(st_ctx *c)
{
    st_system s;
    st_err e;
    st_jw w;
    int i;

    if (st_plat_system(&s, &e)) { st_app_error(c, &e); return; }
    st_resp_json(c->resp, 200, &w);
    st_jw_obj(&w);
    st_jw_kstr(&w, "node", s.node);

    st_jw_key(&w, "os");
    st_jw_obj(&w);
    st_jw_kstr(&w, "name", "OpenVMS");
    st_jw_kstr(&w, "version", s.version);
    st_jw_kstr(&w, "arch", s.arch);
    st_jw_obj_end(&w);

    st_jw_key(&w, "hardware");
    st_jw_obj(&w);
    st_jw_kstr(&w, "model", s.hardware);
    st_jw_kbool(&w, "virtual_machine", s.virtual_machine);
    st_jw_obj_end(&w);

    st_jw_key(&w, "boot_time");
    if (s.boot_time > 0) st_jw_int(&w, s.boot_time); else st_jw_null(&w);

    st_jw_key(&w, "cpu");
    st_jw_obj(&w);
    st_jw_kint(&w, "active", s.cpus_active);
    st_jw_kint(&w, "available", s.cpus_available);
    kull(&w, "idle_ticks", s.cpu_idle_ticks);    /* 100 a second per CPU */
    st_jw_kint(&w, "sampled_at_ms", s.sampled_at_ms);
    st_jw_key(&w, "load");                         /* process states now (no averages on OpenVMS) */
    st_jw_obj(&w);
    st_jw_kint(&w, "current", s.load_current);
    st_jw_kint(&w, "computable", s.load_computable);
    st_jw_kint(&w, "computable_outswapped", s.load_computable_out);
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);

    st_jw_key(&w, "memory");
    st_jw_obj(&w);
    kull(&w, "total", s.mem_total);
    kull(&w, "free", s.mem_free);
    kull(&w, "modified", s.mem_modified);
    kull(&w, "in_use", s.mem_total > s.mem_free + s.mem_modified ? s.mem_total - s.mem_free - s.mem_modified : 0);
    st_jw_obj_end(&w);

    st_jw_key(&w, "paging");
    st_jw_obj(&w);
    kull(&w, "total", s.page_total);
    kull(&w, "used", s.page_used);
    st_jw_obj_end(&w);

    st_jw_key(&w, "disks");
    st_jw_arr(&w);
    for (i = 0; i < s.ndisks; i++) {
        const st_disk *d = &s.disks[i];
        st_jw_obj(&w);
        st_jw_kstr(&w, "device", d->device);
        st_jw_kstr(&w, "label", d->label);
        st_jw_kstr(&w, "logical_volume", d->logical_volume);
        st_jw_kstr(&w, "filesystem", d->filesystem);
        kull(&w, "total", d->total);
        kull(&w, "free", d->free);
        st_jw_kbool(&w, "system_disk", d->system_disk);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);

    st_jw_key(&w, "processes");
    st_jw_obj(&w);
    st_jw_kint(&w, "count", s.processes);
    st_jw_kint(&w, "hidden", s.processes_hidden);   /* not visible to you (WORLD) */
    st_jw_key(&w, "interactive");
    st_jw_arr(&w);
    for (i = 0; i < s.nsessions; i++) {
        st_jw_obj(&w);
        st_jw_kstr(&w, "username", s.sessions[i].username);
        st_jw_kint(&w, "sessions", s.sessions[i].sessions);
        st_jw_obj_end(&w);
    }
    st_jw_arr_end(&w);
    st_jw_obj_end(&w);

    st_jw_key(&w, "queues");
    st_jw_obj(&w);
    st_jw_kint(&w, "count", s.queues);
    st_jw_kint(&w, "batch", s.queues_batch);
    st_jw_kint(&w, "output", s.queues_output);
    st_jw_kint(&w, "stopped", s.queues_stopped);
    st_jw_key(&w, "jobs");
    st_jw_obj(&w);
    st_jw_kint(&w, "executing", s.jobs_executing);
    st_jw_kint(&w, "pending", s.jobs_pending);
    st_jw_kint(&w, "holding", s.jobs_holding);
    st_jw_kint(&w, "timed", s.jobs_timed);
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);

    st_jw_key(&w, "cluster");
    st_jw_obj(&w);
    st_jw_kbool(&w, "member", s.cluster_member);
    if (s.cluster_member) {
        st_jw_kint(&w, "nodes", s.cluster_nodes);
        st_jw_kint(&w, "votes", s.cluster_votes);
        st_jw_kint(&w, "quorum", s.cluster_quorum);
    }
    st_jw_obj_end(&w);
    st_jw_obj_end(&w);
}
