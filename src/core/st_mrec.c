/* st_mrec.c - the recording's records and ring arithmetic (D22). See st_mrec.h. */
#include <string.h>
#include "st_mrec.h"

/* Offsets. The header's and a reading's share the first eight bytes. */
#define MR_KEY       0      /* 4, big-endian */
#define MR_MARK      4      /* 4: "SMH1" header, "SMR1" reading */
/* header */
#define MH_INTERVAL  8      /* 4 */
#define MH_SLOTS     12     /* 4 */
#define MH_STARTED   16     /* 8 */
#define MH_UPDATED   24     /* 8 */
/* reading */
#define MR_TIME      8      /* 8 */
#define MR_CPUS      16     /* 4 */
#define MR_PROCS     20     /* 4 */
#define MR_MODES     24     /* 8 each, 7 */
#define MR_STATES    80     /* 4 each, 14 */
#define MR_MEM       136    /* 8 each: total, free, modified */
#define MR_COUNTERS  160    /* 4 each, 8 */
#define MR_NDISKS    192    /* 4 */
#define MR_DISKS     196    /* 36 each, 32: device (32, NUL-padded), operations (4) */
#define MR_DISK_LEN  36

static void put32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char) v; p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) (v >> 16); p[3] = (unsigned char) (v >> 24);
}

static unsigned int get32(const unsigned char *p)
{
    return (unsigned int) p[0] | (unsigned int) p[1] << 8 | (unsigned int) p[2] << 16 |
           (unsigned int) p[3] << 24;
}

static void put64(unsigned char *p, long long v)
{
    unsigned long long u = (unsigned long long) v;
    int i;
    for (i = 0; i < 8; i++) { p[i] = (unsigned char) (u & 0xFF); u >>= 8; }
}

static long long get64(const unsigned char *p)
{
    unsigned long long u = 0;
    int i;
    for (i = 7; i >= 0; i--) u = (u << 8) | p[i];
    return (long long) u;
}

static unsigned int get_key(const unsigned char *p)
{
    return (unsigned int) p[0] << 24 | (unsigned int) p[1] << 16 | (unsigned int) p[2] << 8 |
           (unsigned int) p[3];
}

void st_mrec_key(unsigned int slot, unsigned char key[ST_MREC_KEY_SIZE])
{
    key[0] = (unsigned char) (slot >> 24); key[1] = (unsigned char) (slot >> 16);
    key[2] = (unsigned char) (slot >> 8);  key[3] = (unsigned char) slot;
}

void st_mrec_encode_header(const st_mrec_header *h, unsigned char rec[ST_MREC_SIZE])
{
    memset(rec, 0, ST_MREC_SIZE);
    st_mrec_key(0, rec + MR_KEY);
    memcpy(rec + MR_MARK, "SMH1", 4);
    put32(rec + MH_INTERVAL, h->interval_secs);
    put32(rec + MH_SLOTS, h->slots);
    put64(rec + MH_STARTED, h->started_ms);
    put64(rec + MH_UPDATED, h->updated_ms);
}

int st_mrec_decode_header(const unsigned char *rec, size_t len, st_mrec_header *h)
{
    memset(h, 0, sizeof *h);
    if (len != ST_MREC_SIZE || get_key(rec + MR_KEY) != 0 || memcmp(rec + MR_MARK, "SMH1", 4)) return -1;
    h->interval_secs = get32(rec + MH_INTERVAL);
    h->slots = get32(rec + MH_SLOTS);
    h->started_ms = get64(rec + MH_STARTED);
    h->updated_ms = get64(rec + MH_UPDATED);
    if (h->interval_secs == 0 || h->interval_secs > 86400 || h->slots == 0 || h->slots > ST_MREC_MAX_SLOTS) {
        memset(h, 0, sizeof *h);
        return -1;
    }
    return 0;
}

void st_mrec_encode(const st_monitor *m, unsigned int slot, unsigned char rec[ST_MREC_SIZE])
{
    int i, nd = m->ndisks < 0 ? 0 : m->ndisks > ST_MAX_DISKS ? ST_MAX_DISKS : m->ndisks;
    memset(rec, 0, ST_MREC_SIZE);
    st_mrec_key(slot, rec + MR_KEY);
    memcpy(rec + MR_MARK, "SMR1", 4);
    put64(rec + MR_TIME, m->sampled_at_ms);
    put32(rec + MR_CPUS, m->cpus);
    put32(rec + MR_PROCS, m->processes);
    for (i = 0; i < ST_MON_MODES; i++) put64(rec + MR_MODES + 8 * i, m->modes[i]);
    for (i = 0; i < ST_MON_STATES; i++) put32(rec + MR_STATES + 4 * i, m->states[i]);
    put64(rec + MR_MEM, (long long) m->mem_total);
    put64(rec + MR_MEM + 8, (long long) m->mem_free);
    put64(rec + MR_MEM + 16, (long long) m->mem_modified);
    for (i = 0; i < ST_MON_COUNTERS; i++) put32(rec + MR_COUNTERS + 4 * i, m->counters[i]);
    put32(rec + MR_NDISKS, (unsigned int) nd);
    for (i = 0; i < nd; i++) {
        unsigned char *d = rec + MR_DISKS + MR_DISK_LEN * i;
        size_t n = strlen(m->disks[i].device);
        memcpy(d, m->disks[i].device, n > 31 ? 31 : n);
        put32(d + 32, m->disks[i].operations);
    }
}

int st_mrec_decode(const unsigned char *rec, size_t len, st_monitor *m, unsigned int *slot)
{
    unsigned int nd;
    int i;
    memset(m, 0, sizeof *m);
    if (len != ST_MREC_SIZE || memcmp(rec + MR_MARK, "SMR1", 4)) return -1;
    *slot = get_key(rec + MR_KEY);
    nd = get32(rec + MR_NDISKS);
    if (*slot == 0 || nd > ST_MAX_DISKS) return -1;
    m->sampled_at_ms = get64(rec + MR_TIME);
    m->cpus = get32(rec + MR_CPUS);
    m->processes = get32(rec + MR_PROCS);
    for (i = 0; i < ST_MON_MODES; i++) m->modes[i] = get64(rec + MR_MODES + 8 * i);
    for (i = 0; i < ST_MON_STATES; i++) m->states[i] = get32(rec + MR_STATES + 4 * i);
    m->mem_total = (unsigned long long) get64(rec + MR_MEM);
    m->mem_free = (unsigned long long) get64(rec + MR_MEM + 8);
    m->mem_modified = (unsigned long long) get64(rec + MR_MEM + 16);
    for (i = 0; i < ST_MON_COUNTERS; i++) m->counters[i] = get32(rec + MR_COUNTERS + 4 * i);
    m->ndisks = (int) nd;
    for (i = 0; i < (int) nd; i++) {
        const unsigned char *d = rec + MR_DISKS + MR_DISK_LEN * i;
        memcpy(m->disks[i].device, d, 31);
        m->disks[i].device[31] = '\0';
        m->disks[i].operations = get32(d + 32);
    }
    return 0;
}

unsigned int st_mrec_slots(unsigned int interval_secs, unsigned int days)
{
    unsigned long long n;
    if (interval_secs == 0) return 1;
    n = (unsigned long long) days * 86400u / interval_secs;
    if (n < 1) n = 1;
    if (n > ST_MREC_MAX_SLOTS) n = ST_MREC_MAX_SLOTS;
    return (unsigned int) n;
}

long long st_mrec_nearest(long long t_ms, unsigned int interval_secs)
{
    long long step = (long long) interval_secs * 1000;
    if (step <= 0 || t_ms < 0) return 0;
    return (t_ms + step / 2) / step * step;
}

unsigned int st_mrec_slot(long long t_ms, unsigned int interval_secs, unsigned int slots)
{
    long long step = (long long) interval_secs * 1000;
    if (step <= 0 || slots == 0) return 1;
    return 1 + (unsigned int) ((st_mrec_nearest(t_ms, interval_secs) / step) % slots);
}

int st_mrec_matches(long long rec_ms, long long want_ms, unsigned int interval_secs)
{
    return rec_ms > 0 && st_mrec_nearest(rec_ms, interval_secs) == want_ms;
}

int st_mrec_plan(long long now_ms, unsigned int minutes, unsigned int points,
                 const st_mrec_header *h, st_mrec_point *out, int max, unsigned int *step_secs)
{
    long long step, last, oldest, span, t;
    unsigned long long k;
    int n = 0, i;

    *step_secs = 0;
    if (!h->interval_secs || !h->slots || points < 2 || minutes == 0 || max <= 0 || now_ms <= 0) return 0;
    /* A whole number of intervals: ceil(span / points / interval) of them, the span no
       longer than the ring holds, so a month asked of a week spreads over the week. */
    span = (long long) minutes * 60;
    if (span > (long long) h->slots * h->interval_secs) span = (long long) h->slots * h->interval_secs;
    k = (unsigned long long) ((span + (long long) points * h->interval_secs - 1) /
                              ((long long) points * h->interval_secs));
    if (k < 1) k = 1;
    step = (long long) k * h->interval_secs * 1000;
    *step_secs = (unsigned int) (k * h->interval_secs);
    /* The newest boundary at or before now, and nothing older than the ring holds (the
       slot it would be in has been written again since) or than the range asks. */
    last = now_ms / ((long long) h->interval_secs * 1000) * ((long long) h->interval_secs * 1000);
    oldest = now_ms - span * 1000;
    t = last - ((long long) h->slots - 1) * h->interval_secs * 1000;
    if (t > oldest) oldest = t;
    for (t = last; t >= oldest && n < max; t -= step) {
        out[n].want_ms = t;
        out[n].slot = st_mrec_slot(t, h->interval_secs, h->slots);
        n++;
    }
    for (i = 0; i < n / 2; i++) {   /* oldest first */
        st_mrec_point x = out[i];
        out[i] = out[n - 1 - i];
        out[n - 1 - i] = x;
    }
    return n;
}
