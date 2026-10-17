/* st_mrec.h - monitoring readings and the recording's records (Phase 13, D21, D22).
   No I/O.

   A reading is what OpenVMS's counters say at one moment (st_plat_monitor). The
   recorder (steward -r, D22) writes one every interval into a ring of fixed-length
   records, an RMS indexed file keyed by slot; the pool reads them back for
   GET api/v1/monitor/history. Records are encoded here with explicit offsets, never as
   a struct (CLAUDE.md): integers little-endian, except the key, which is big-endian so
   that RMS's string key orders it as a number.

   Key 0 is the header: the interval and the number of slots, when the recorder started
   and when it last wrote. Keys 1..slots hold readings: the slot of a reading is
   1 + (the interval boundary nearest its time / interval) mod slots. Each record keeps
   its own time, so one left from an earlier lap or an earlier interval is told apart
   by st_mrec_matches and skipped. Processes are never recorded (D22). */
#ifndef ST_MREC_H
#define ST_MREC_H

#include <stddef.h>

#define ST_MAX_DISKS 32

enum { ST_MON_INTERRUPT, ST_MON_MPSYNCH, ST_MON_KERNEL, ST_MON_EXEC, ST_MON_SUPER,
       ST_MON_USER, ST_MON_IDLE, ST_MON_MODES };
enum { ST_MON_CUR, ST_MON_COM, ST_MON_COMO, ST_MON_LEF, ST_MON_LEFO, ST_MON_HIB,
       ST_MON_HIBO, ST_MON_SUSP, ST_MON_SUSPO, ST_MON_PFW, ST_MON_MWAIT, ST_MON_CEF,
       ST_MON_COLPG, ST_MON_FPG, ST_MON_STATES };
enum { ST_MON_FAULTS, ST_MON_PREADIO, ST_MON_PWRITIO, ST_MON_ISWPCNT, ST_MON_DIRIO,
       ST_MON_BUFIO, ST_MON_MBREADS, ST_MON_MBWRITES, ST_MON_COUNTERS };

typedef struct {
    char         device[32];          /* "DKA0:", as the dashboard names it */
    unsigned int operations;          /* DVI$_OPCNT: wraps at 2^32 */
} st_mon_disk;

typedef struct {
    long long          sampled_at_ms;             /* milliseconds since 1970 UTC */
    unsigned int       cpus;                      /* active */
    /* Ticks summed over CPUs, 100 a second a CPU. Signed: RMI$_CPUINTSTK reads
       negative on the x86 VM (NOTES.md). */
    long long          modes[ST_MON_MODES];
    unsigned int       states[ST_MON_STATES];     /* processes in each state, now */
    unsigned int       processes;                 /* on the system, RMI$_PROCS */
    unsigned long long mem_total, mem_free, mem_modified;   /* bytes */
    unsigned int       counters[ST_MON_COUNTERS]; /* since boot; wrap at 2^32 */
    int                ndisks;
    st_mon_disk        disks[ST_MAX_DISKS];       /* the system disk first */
} st_monitor;

#define ST_MREC_SIZE     1348   /* every record, the header too */
#define ST_MREC_KEY_SIZE 4      /* at offset 0 */
#define ST_MREC_MAX_SLOTS 1000000u

typedef struct {
    unsigned int interval_secs;
    unsigned int slots;
    long long    started_ms;      /* when the recorder started */
    long long    updated_ms;      /* its last write */
} st_mrec_header;

/* The key of a slot (0: the header), as the record holds it. */
void st_mrec_key(unsigned int slot, unsigned char key[ST_MREC_KEY_SIZE]);

void st_mrec_encode_header(const st_mrec_header *h, unsigned char rec[ST_MREC_SIZE]);
/* 0, or -1 if rec is not a header we wrote (wrong size, key or mark, or values out of
   range). */
int  st_mrec_decode_header(const unsigned char *rec, size_t len, st_mrec_header *h);

void st_mrec_encode(const st_monitor *m, unsigned int slot, unsigned char rec[ST_MREC_SIZE]);
/* 0, or -1 if rec is not a reading we wrote. *slot gets its key. */
int  st_mrec_decode(const unsigned char *rec, size_t len, st_monitor *m, unsigned int *slot);

/* Slots for days at interval_secs, at least 1 and at most ST_MREC_MAX_SLOTS. */
unsigned int st_mrec_slots(unsigned int interval_secs, unsigned int days);
/* The interval boundary nearest t_ms, in ms. */
long long    st_mrec_nearest(long long t_ms, unsigned int interval_secs);
/* The slot a reading taken at t_ms goes in: 1..slots. */
unsigned int st_mrec_slot(long long t_ms, unsigned int interval_secs, unsigned int slots);
/* Does a reading taken at rec_ms belong to the boundary want_ms? */
int          st_mrec_matches(long long rec_ms, long long want_ms, unsigned int interval_secs);

/* The readings to fetch for the last `minutes` before now_ms, at most `points` of
   them: boundaries a whole number of intervals apart (*step_secs), oldest first, none
   older than the ring holds (a longer range is cut to it before it is spread). Returns how many (at most max), with each boundary and its
   slot. */
typedef struct { long long want_ms; unsigned int slot; } st_mrec_point;
int st_mrec_plan(long long now_ms, unsigned int minutes, unsigned int points,
                 const st_mrec_header *h, st_mrec_point *out, int max, unsigned int *step_secs);

#endif
