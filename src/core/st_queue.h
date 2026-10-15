/* st_queue.h - batch and print queues (Phase 9, D17): input rules and names. No I/O. */
#ifndef ST_QUEUE_H
#define ST_QUEUE_H

#include <stddef.h>

#define ST_QUEUE_NAME_MAX 31

/* A queue name: 1-31 characters from A-Z, 0-9, '$' and '_', case-insensitive; upper
   case into out. No wildcards: $GETQUI would take them as a search. Returns 1 if
   valid. */
int st_valid_queue_name(const char *in, char out[ST_QUEUE_NAME_MAX + 1]);

/* A job's entry number: 1 to 9 decimal digits, not 0. Returns 1 if valid. */
int st_parse_entry(const char *in, unsigned int *entry);

/* The names of the status bits set, comma-separated, into out: a queue's
   (QUI$_QUEUE_STATUS: stopped, paused, idle, ...) or a job's (QUI$_JOB_STATUS:
   executing, holding, pending, ...), as SHOW QUEUE words them. The bits are QUIDEF's,
   taken from the node's SYS$STARLET_C.TLB. */
void st_queue_status_names(unsigned int status, char *out, size_t outlen);
void st_job_status_names(unsigned int status, char *out, size_t outlen);

/* The queue names in QUI$_GENERIC_TARGET's buffer: one is the bare name (12 bytes for
   X86VMS_BATCH on x86); several are taken as separated by commas, spaces or NULs,
   whichever OpenVMS uses. Up to max names of at most 31 characters into names.
   Returns how many, or -1 if more were there than fit (the caller must then assume
   it cannot tell). */
int st_queue_target_list(const char *buf, size_t len, char names[][32], int max);

#define ST_JOB_INACCESSIBLE 0x8u   /* QUI$M_JOB_INACCESSIBLE: not the viewer's to read */

#endif
