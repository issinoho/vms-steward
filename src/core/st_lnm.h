/* st_lnm.h - logical names (Phase 7, D14): input rules and the parser for
   SHOW LOGICAL/FULL output. No I/O.

   OpenVMS has no service that lists a logical name table, so Steward has SHOW
   LOGICAL/FULL list it, as the viewer (D14), and parses what it prints:

       (LNM$SYSTEM_TABLE)<TAB>[kernel]  [shareable,system]
       <TAB><TAB><TAB>[Protection=(RWC,RWC,R,R)]  [Owner=[SYSTEM]]

         "SYS$SYSROOT" [exec] = "X86VMS$DKA0:[SYS0.]" [concealed,terminal]
       <TAB>= "SYS$COMMON:"

   A table header in parentheses, its protection and owner, then each name: the name
   in quotes, its access mode and attributes in brackets, then its equivalences (one
   per line, the first on the name's line), each with its own attributes. A quote
   inside a quoted string is doubled. */
#ifndef ST_LNM_H
#define ST_LNM_H

#include <stddef.h>

#define ST_LNM_TABLE_MAX 31     /* a table name */
#define ST_LNM_NAME_MAX  255    /* a logical name or an equivalence string */
#define ST_LNM_PATTERN_MAX 63
#define ST_LNM_MAXEQ     16     /* equivalences kept per name (OpenVMS allows 128) */

typedef struct {
    char name[ST_LNM_TABLE_MAX + 1];
    char mode[8];               /* kernel, exec, super, user */
    char attributes[64];        /* e.g. "shareable,system" */
    char protection[40];        /* e.g. "(RWC,RWC,R,R)" */
    char owner[48];             /* e.g. "[SYSTEM]" */
} st_lnm_table;

typedef struct {
    char value[ST_LNM_NAME_MAX + 1];
    char attributes[48];        /* e.g. "concealed,terminal" */
} st_lnm_eq;

typedef struct {
    char      name[ST_LNM_NAME_MAX + 1];
    char      mode[8];
    char      attributes[64];   /* name attributes: no_alias, confine, table, clusterwide */
    int       neq;              /* equivalences shown (up to ST_LNM_MAXEQ) */
    int       more;             /* equivalences past ST_LNM_MAXEQ, not kept */
    st_lnm_eq eq[ST_LNM_MAXEQ];
} st_lnm;

/* A table name as Steward accepts one: 1-31 characters from A-Z, 0-9, '$' and '_',
   case-insensitive; upper case into out. Refused, whatever their case: the tables
   that are the *process's own*, or that search it. Under a persona those are the
   service's (its settings, the gateway secret among them, are process logical names),
   never the viewer's. Returns 1 if valid. */
int st_valid_lnm_table(const char *in, char out[ST_LNM_TABLE_MAX + 1]);

/* A SHOW LOGICAL pattern: 1-63 characters from A-Z, 0-9, '$', '_', '*' and '%';
   upper case into out. Returns 1 if valid. */
int st_valid_lnm_pattern(const char *in, char out[ST_LNM_PATTERN_MAX + 1]);

/* A logical name to translate: 1-255 printable ASCII characters, kept as given
   (names are case-sensitive; DCL upper-cases only unquoted ones). Returns 1 if valid. */
int st_valid_lnm_name(const char *in);

/* The parser: feed it SHOW LOGICAL/FULL's lines one by one; it calls back once per
   name, with the table the name is in. A callback returning nonzero stops it. */
typedef int (*st_lnm_cb)(const st_lnm_table *t, const st_lnm *n, void *ctx);

typedef struct {
    st_lnm_table table;
    st_lnm       cur;
    int          have;          /* cur holds a name not yet passed on */
    int          stopped;
    int          tables;        /* table headers seen */
    char         message[128];  /* the last %FACILITY-L-IDENT line, if any */
    st_lnm_cb    fn;
    void        *ctx;
} st_lnm_parser;

void st_lnm_parse_init(st_lnm_parser *p, st_lnm_cb fn, void *ctx);
/* One line, without its line terminator. Returns 1 once the callback has stopped it. */
int  st_lnm_parse_line(st_lnm_parser *p, const char *line, size_t len);
/* The end of the output: passes on the last name. */
int  st_lnm_parse_end(st_lnm_parser *p);

#endif
