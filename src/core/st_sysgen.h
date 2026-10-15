/* st_sysgen.h - system parameters (Phase 10, D18): the parser for SYSGEN SHOW/ALL's
   output. No I/O.

   OpenVMS has no service that gives SYSGEN's defaults, limits and units, so Steward has
   SYSGEN SHOW/ALL print them, as the viewer (the D14 helper), and parses its fixed
   columns (x86 E9.2-4, measured on its output):

   Parameter Name            Current    Default     Min.       Max.   Unit  Dynamic
   GBLSECTIONS                  1440       1024        80      65535 Sections
    internal value             85120       8192      1024    8388608 Pages      D
   SCSNODE                 "X86VMS  "    "    "    "    "     "ZZZZ" Ascii
   SCH_SOFT_OFFLD         (none set) (none set)         0       1023 CPU bitmap D

   The name runs to its first blank; the current, default, minimum and maximum end in
   columns 33 (34 for a quoted string), 44, 54 and 65; the unit is columns 66 to 75; a "D" in column 77 marks a
   dynamic parameter. A value may hold blanks ("(none set)", a quoted string). An
   "internal value" line belongs to the parameter above it. */
#ifndef ST_SYSGEN_H
#define ST_SYSGEN_H

#include <stddef.h>

typedef struct {
    char current[40], dflt[40], min[40], max[40], unit[16];
} st_param_values;

typedef struct {
    char            name[32];
    st_param_values v;
    int             dynamic;
    int             ascii;          /* a string parameter: the values without quotes */
    int             has_internal;
    st_param_values internal;       /* its "internal value" line, in pages */
} st_param;

typedef int (*st_param_cb)(const st_param *p, void *ctx);   /* nonzero stops */

typedef struct {
    st_param    cur;
    int         have, stopped;
    st_param_cb fn;
    void       *ctx;
} st_sysgen_parser;

void st_sysgen_init(st_sysgen_parser *p, st_param_cb fn, void *ctx);
/* One line, without its terminator. Returns 1 once the callback has stopped it. */
int  st_sysgen_line(st_sysgen_parser *p, const char *line, size_t len);
/* The end of the output: passes on the last parameter. */
int  st_sysgen_end(st_sysgen_parser *p);

#endif
