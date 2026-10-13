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
   that are the *process's own*, or that search it, and every job table by its own
   name (LNM$JOB_<address>). Under a persona those are the service's (its settings,
   the gateway secret among them, are process logical names), never the viewer's.
   Returns 1 if valid. */
int st_valid_lnm_table(const char *in, char out[ST_LNM_TABLE_MAX + 1]);

/* A SHOW LOGICAL pattern: 1-63 characters from A-Z, 0-9, '$', '_', '*' and '%';
   upper case into out. Returns 1 if valid. */
int st_valid_lnm_pattern(const char *in, char out[ST_LNM_PATTERN_MAX + 1]);

/* A logical name to translate: 1-255 printable ASCII characters, kept as given
   (names are case-sensitive; DCL upper-cases only unquoted ones). Returns 1 if valid. */
int st_valid_lnm_name(const char *in);

/* ---- changes (Phase 7b, D15) ---- */

/* Access modes, as OpenVMS numbers them (PSL$C_*). Kernel is never accepted. */
#define ST_LNM_EXEC  1
#define ST_LNM_SUPER 2
#define ST_LNM_USER  3

#define ST_LNM_CONFINE   1u     /* name attributes */
#define ST_LNM_NO_ALIAS  2u
#define ST_LNM_CONCEALED 1u     /* equivalence attributes */
#define ST_LNM_TERMINAL  2u

typedef struct {
    char     value[ST_LNM_NAME_MAX + 1];
    unsigned attrs;             /* ST_LNM_CONCEALED, ST_LNM_TERMINAL */
} st_lnm_defeq;

/* A name to define. At most ST_LNM_MAXEQ equivalences: as many as the views show, so
   a name read back can always be written back whole. */
typedef struct {
    char         table[ST_LNM_TABLE_MAX + 1];   /* as st_valid_lnm_table gave it */
    char         name[ST_LNM_NAME_MAX + 1];
    int          mode;          /* ST_LNM_EXEC, _SUPER or _USER */
    unsigned     attrs;         /* ST_LNM_CONFINE, ST_LNM_NO_ALIAS */
    int          replace;       /* replace a name already at that mode */
    int          neq;
    st_lnm_defeq eq[ST_LNM_MAXEQ];
} st_lnm_def;

/* "user", "super" or "exec" (or "supervisor", "executive"), in any case, to
   ST_LNM_*; -1 for anything else, kernel included. */
int st_lnm_mode(const char *s);
/* ST_LNM_* (and 0, kernel) to its name; "?" otherwise. */
const char *st_lnm_mode_name(int mode);

struct st_jval;
/* The body of PUT api/v1/logical: {"table", "name", "mode", "attributes": [...],
   "equivalences": [{"value", "attributes": [...]}], "replace"}. Every member but
   attributes and replace is required, nothing else is allowed. Returns 0, or -1 with
   *why naming the problem (a constant string). */
int st_lnm_def_parse(const struct st_jval *root, st_lnm_def *d, const char **why);

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
