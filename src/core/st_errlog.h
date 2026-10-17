/* st_errlog.h - the error log (Phase 14, D23): parsers for what STEWARD_ERRLOG.COM
   writes (ELV's translation of ERRLOG.SYS), for CLUE's crash listings and for OPCOM's
   log. No I/O.

   ERRLOG.SYS's format is not documented, and the classic ANALYZE/ERROR_LOG is not on
   x86, so the D14 helper, which is the viewer, runs ELV into the reply mailbox, in one
   part, as for the products (st_product.h):

   %%PART%% EVENTS          ANALYZE/ERROR_LOG/ELV TRANSLATE/ONE_LINE[/SINCE=-<days>-]
   Output for SYS$SYSROOT:[SYSERR]ERRLOG.SYS;1

   EVENT  EVENT_TYPE_____________________________  TIMESTAMP______________  NODE__  EVENT_CLASS____...
   1766   Time Stamp                               10-OCT-2026 14:04:28.88  X86VMS  CONTROL_ENTRIES
   %%STATUS%% 00000001

   or %%PART%% ENTRY, /ENTRY=(START:n,END:n): the same row for the one event, then its
   fields under a second heading, a row each, in groups parted by blank lines:

   DESCRIPTION__________________________________   RANGE___   VALUE_____________   TRANSLATED_VALUE____...
      Hardware Architecture                                   5                    Intel X86
      Processor Status                             <63:00>:   0x0000000000000000
         Current Mode                              <04:03>:   0x0                  Kernel
      Message
      CPU   0 LID: 0x00000000  Die: 0xFFFF Package:  0 Core:  0 Thread  0 ACPI:    0

   The underscored headings give each column's start and width. A line whose text runs
   across the gap before RANGE is free text belonging to the field above (a message's
   lines). ELV's own messages ("%ELV-E-FILOPNERR, error opening ...", "-RMS-E-FNF, file
   not found") are kept: without access to the file ELV says so and still exits with
   success (NOTES.md), so its messages, not its status, tell a refusal.

   CLUE writes a listing for each crash, SYS$ERRORLOG:CLUE$<node>_<ddmmyy>_<hhmm>.LIS,
   whose first page is a "Crashdump Summary" of "Name:   value" lines (Crash Time,
   Bugcheck Type, Current Process, Current Image, Failing PC, Module, Boot Time, System
   Uptime, ...), up to "Stack Pointers:".

   OPCOM's log is a text file of messages, each a header line
   "%%%%%%%%%%%  OPCOM  16-OCT-2026 12:06:03.53  %%%%%%%%%%%" and its lines, usually
   "Message from user SYSTEM on X86VMS" and then the text, parted by blank lines. */
#ifndef ST_ERRLOG_H
#define ST_ERRLOG_H

#include <stddef.h>

/* ---- ELV ---- */

enum { ST_ELV_LIST = 0, ST_ELV_ENTRY };

typedef struct {
    unsigned int number;
    char type[48], when[24], iso[20], node[16], cls[48];   /* when as ELV gives it; iso local */
} st_elv_event;

typedef struct {
    int  indent;              /* 0 for a top-level field, 1, 2 for its bit fields */
    int  text;                /* 1: a line of free text (description holds it) */
    int  group;               /* starts a new group (after a blank line) */
    char description[80], range[16], value[48], translated[80];
} st_elv_field;

typedef int  (*st_elv_event_cb)(const st_elv_event *ev, void *ctx);
typedef int  (*st_elv_field_cb)(const st_elv_field *f, void *ctx);

typedef struct {
    st_elv_event_cb event_fn;
    st_elv_field_cb field_fn;
    void *ctx;
    int  part;                /* -1 outside a part */
    int  seen, status_seen;
    unsigned int status;      /* the part's %%STATUS%% */
    int  in_fields, blank, stop;
    int  ec[5], fc[4];        /* column starts: events (5), fields (4) */
    int  ew[5];               /* event column widths, the last one open */
    int  nevents, nfields;
    char message[256];        /* ELV's first message, with its continuation */
} st_elv_parser;

void st_elv_init(st_elv_parser *p, st_elv_event_cb ev, st_elv_field_cb fl, void *ctx);
void st_elv_line(st_elv_parser *p, const char *line, size_t len);
/* Did ELV refuse the file (its message says so)? */
int  st_elv_refused(const st_elv_parser *p);

/* "13-OCT-2026 15:33:12.11" to "2026-10-13T15:33:12"; "" if it is not such a time. */
void st_vms_time_iso(const char *vms, char iso[20]);

/* ---- CLUE crash listings ---- */

#define ST_CLUE_MAX_ITEMS 32

typedef struct { char key[32]; char value[128]; } st_clue_item;

typedef struct {
    int  nitems, done, lines;
    st_clue_item items[ST_CLUE_MAX_ITEMS];
} st_clue_summary;

void st_clue_init(st_clue_summary *s);
/* Feed the listing's lines until s->done. */
void st_clue_line(st_clue_summary *s, const char *line, size_t len);
const char *st_clue_get(const st_clue_summary *s, const char *key);   /* "" if absent */
/* CLUE$<node>_<ddmmyy>_<hhmm>.LIS, upper case: the only names Steward opens. */
int  st_valid_clue_name(const char *name);

/* ---- OPCOM's log ---- */

typedef struct {
    char when[24], iso[20];
    char from[32], node[16];  /* "Message from user <from> on <node>", if it starts so */
    char text[1024];          /* the rest, lines joined with \n */
    int  stamp;               /* "Logfile time stamp" */
} st_opcom_msg;

typedef int (*st_opcom_cb)(const st_opcom_msg *m, void *ctx);

typedef struct {
    st_opcom_cb fn;
    void *ctx;
    int  open, stop;
    st_opcom_msg cur;
} st_opcom_parser;

void st_opcom_init(st_opcom_parser *p, st_opcom_cb fn, void *ctx);
void st_opcom_line(st_opcom_parser *p, const char *line, size_t len);
void st_opcom_end(st_opcom_parser *p);

#endif
