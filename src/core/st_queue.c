/* st_queue.c - queues: input rules and names (st_queue.h). */
#include <string.h>
#include "st_queue.h"
#include "st_buf.h"

int st_valid_queue_name(const char *in, char out[ST_QUEUE_NAME_MAX + 1])
{
    size_t i, n = strlen(in);
    if (n < 1 || n > ST_QUEUE_NAME_MAX) return 0;
    for (i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z') c = (char) (c - 'a' + 'A');
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '$' || c == '_')) return 0;
        out[i] = c;
    }
    out[n] = '\0';
    return 1;
}

int st_parse_entry(const char *in, unsigned int *entry)
{
    unsigned int v = 0;
    size_t i, n = strlen(in);
    if (n < 1 || n > 9) return 0;
    for (i = 0; i < n; i++) {
        if (in[i] < '0' || in[i] > '9') return 0;
        v = v * 10 + (unsigned int) (in[i] - '0');
    }
    if (!v) return 0;
    *entry = v;
    return 1;
}

typedef struct { unsigned int bit; const char *name; } bitname;

static void names(const bitname *t, size_t n, unsigned int status, char *out, size_t outlen)
{
    size_t i;
    out[0] = '\0';
    for (i = 0; i < n; i++)
        if (status & t[i].bit) {
            if (*out) st_append(out, outlen, ",");
            st_append(out, outlen, t[i].name);
        }
}

void st_queue_status_names(unsigned int status, char *out, size_t outlen)
{
    /* QUI$M_QUEUE_* status bits (QUIDEF, x86 E9.2-4). */
    static const bitname t[] = {
        { 0x1, "aligning" }, { 0x2, "idle" }, { 0x4, "lowercase" }, { 0x8, "operator_request" },
        { 0x10, "paused" }, { 0x20, "pausing" }, { 0x40, "remote" }, { 0x80, "resetting" },
        { 0x100, "resuming" }, { 0x200, "server" }, { 0x400, "stalled" }, { 0x800, "starting" },
        { 0x1000, "stopped" }, { 0x2000, "stopping" }, { 0x4000, "unavailable" }, { 0x8000, "closed" },
        { 0x10000, "busy" }, { 0x20000, "undefined" }, { 0x40000, "available" }, { 0x80000, "disabled" },
        { 0x100000, "autostart_inactive" }, { 0x200000, "stop_pending" },
    };
    names(t, sizeof t / sizeof t[0], status, out, outlen);
}

void st_job_status_names(unsigned int status, char *out, size_t outlen)
{
    /* QUI$M_JOB_* status bits (QUIDEF, x86 E9.2-4). */
    static const bitname t[] = {
        { 0x1, "aborting" }, { 0x2, "executing" }, { 0x4, "holding" }, { 0x8, "inaccessible" },
        { 0x10, "refused" }, { 0x20, "requeue" }, { 0x40, "restarting" }, { 0x80, "retained" },
        { 0x100, "starting" }, { 0x200, "timed_release" }, { 0x400, "suspended" }, { 0x800, "pending" },
        { 0x1000, "undefined" }, { 0x2000, "stalled" }, { 0x4000, "incomplete" }, { 0x8000, "completing" },
    };
    names(t, sizeof t / sizeof t[0], status, out, outlen);
}

int st_queue_target_list(const char *buf, size_t len, char names[][32], int max)
{
    size_t i = 0;
    int n = 0;
    while (i < len) {
        size_t k = 0;
        while (i < len && (buf[i] == ',' || buf[i] == ' ' || buf[i] == '\0')) i++;
        if (i >= len) break;
        if (n >= max) return -1;
        while (i + k < len && buf[i + k] != ',' && buf[i + k] != ' ' && buf[i + k] != '\0') k++;
        if (k > 31) return -1;   /* not a queue name: cannot tell */
        memcpy(names[n], buf + i, k);
        names[n][k] = '\0';
        n++;
        i += k;
    }
    return n;
}

