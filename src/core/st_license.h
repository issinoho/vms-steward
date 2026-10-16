/* st_license.h - licences (Phase 11, D19): the parser for what STEWARD_LICENSE.COM
   writes. No I/O.

   OpenVMS has no documented service that lists licences, so the D14 helper, which is
   the viewer, runs three LMF commands, each into the reply mailbox, each in its part:

   %%PART%% LOADED          SHOW LICENSE/FULL: the licences loaded on this node
   Active licenses on node X86VMS:
   BASIC                    a product at column 0, its fields indented by a tab
   <tab>Producer: VSI
   <tab>Per Core License    (a line without a colon: a flag, or the options)
   <tab>X86_64
   %%STATUS%% 00000001      the command's $STATUS, in hexadecimal
   %%PART%% CHARGE          SHOW LICENSE/UNIT_REQUIREMENTS: this node's charge
   Type: PCL,   Units Required: 2  (X86_64 Per Core)
   %%STATUS%% 00000001
   %%PART%% DATABASE        LICENSE LIST/FULL: the LMF$LICENSE database
   License Database File:       SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB;1
   -----------------------------------      starts each PAK
   Product Name:                BASIC       "Label:" at column 0, the value after it
   [End Of List]
   %%STATUS%% 1001829C      (%RMS-F-PRV when the viewer may not read the database)

   A field this parser does not name is kept in other[], so nothing OpenVMS shows is
   lost; an indented line in the database listing continues the field above it. */
#ifndef ST_LICENSE_H
#define ST_LICENSE_H

#include <stddef.h>

enum { ST_LIC_LOADED = 0, ST_LIC_CHARGE, ST_LIC_DATABASE, ST_LIC_PARTS };

#define ST_LIC_OTHER  6
#define ST_LIC_CHARGE_LINES 8

typedef struct {
    int  part;                      /* ST_LIC_LOADED or ST_LIC_DATABASE */
    char product[32], producer[32], issuer[32], authorization[64];
    char units[16], version[16], release[32], termination[32];
    char availability[16], activity[16], options[96], hardware_id[96];
    char revision[8], status[24], command[16], modified_by[32], modified_on[32];
    int  per_core;
    int  nother;
    char other_label[ST_LIC_OTHER][32], other_value[ST_LIC_OTHER][96];
} st_license;

typedef int (*st_license_cb)(const st_license *l, void *ctx);   /* nonzero stops */

typedef struct {
    st_license    cur;
    int           have, stopped, part;   /* part: -1 before the first marker */
    char         *last;                  /* the field a continuation line adds to */
    size_t        lastlen;
    char          node[32];
    int           ncharge;
    char          charge[ST_LIC_CHARGE_LINES][128];
    char          charge_type[16], charge_units[16];
    char          db_file[128], db_created[32], db_created_by[32], db_version[16];
    int           seen[ST_LIC_PARTS];    /* its %%STATUS%% line came */
    unsigned int  status[ST_LIC_PARTS];
    st_license_cb fn;
    void         *ctx;
} st_license_parser;

void st_license_init(st_license_parser *p, st_license_cb fn, void *ctx);
/* One line, without its terminator. Returns 1 once the callback has stopped it. */
int  st_license_line(st_license_parser *p, const char *line, size_t len);
/* The end of the output: passes on the last licence. */
int  st_license_end(st_license_parser *p);
/* Did part run and succeed? */
int  st_license_ok(const st_license_parser *p, int part);

#endif
