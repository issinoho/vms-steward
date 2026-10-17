/* st_platform.h - everything Steward needs from the operating system.

   Implemented by plat/vms/ (system services) and plat/stub/ (an in-memory fake for
   Linux tests and front-end work). Keep this free of OpenVMS types: condition values
   travel as plain unsigned ints, together with their message text, and privilege
   masks as two longwords.

   Strings crossing this interface are ISO-8859-1, as OpenVMS stores them. */
#ifndef ST_PLATFORM_H
#define ST_PLATFORM_H

#include <stddef.h>
#include "st_lnm.h"
#include "st_sysgen.h"
#include "st_license.h"
#include "st_product.h"

/* What went wrong, in terms the HTTP layer can map to a status. */
enum {
    ST_OK = 0,
    ST_E_NOPRIV,      /* the OS refused: 403 */
    ST_E_NOTFOUND,    /* 404 */
    ST_E_INVALID,     /* the OS rejected a value: 422 */
    ST_E_CONFLICT,    /* 409 */
    ST_E_INTERNAL     /* anything else: 500 */
};

typedef struct {
    int          kind;
    unsigned int cond;        /* OpenVMS condition value, 0 if none */
    char         text[256];   /* its $GETMSG text, or a description */
} st_err;

typedef struct {
    const char *session_file;
    const char *audit_file;
} st_plat_config;

int  st_plat_init(const st_plat_config *cfg, st_err *e);

/* ---- authentication (SYS$ACM on OpenVMS) ---- */
enum { ST_AUTH_OK = 0, ST_AUTH_FAILED, ST_AUTH_EXPIRED, ST_AUTH_ERROR };

/* username: validated upper case (st_valid_username). client: the browser's address,
   passed to the OS so intrusion records name the client (docs/PHASE1.md).
   e->text gets the OS's reason (e.g. "account is disabled") for the audit log only:
   it must not reach the client, which would let it probe for usernames. */
int  st_plat_authenticate(const char *username, const char *password,
                          const char *client, st_err *e);

/* ---- personas ---- */
/* Become username for the current request, with the user's default privileges plus
   those in enable (a quadword mask) that the user is authorized for (D9). OpenVMS
   refuses the rest, so enable can never grant more than the user holds. Fails if a
   persona is already active: that means an earlier request did not end its own,
   which is a bug. */
int  st_plat_persona_begin(const char *username, const unsigned int enable[2], st_err *e);
/* Within the active persona: defaults plus enable, as above, dropping anything
   enabled before. */
int  st_plat_persona_set_privs(const unsigned int enable[2], st_err *e);
/* Return to the service's own identity. Safe to call when no persona is active. */
void st_plat_persona_end(void);
int  st_plat_persona_active(void);
/* 1 if the service's own identity holds only its baseline privileges, i.e. the
   privilege it needs briefly to create personas (SYSPRV on OpenVMS, D2) is off
   again. Checked after every request; anything else stops the process. */
int  st_plat_privileges_clean(void);

/* ---- the current persona ---- */
#define ST_MAX_IDS 64
typedef struct {
    char         username[13];
    char         owner[33];
    char         account[9];
    unsigned int uic;               /* group << 16 | member */
    unsigned int priv_auth[2];      /* authorized privileges, quadword */
    unsigned int priv_def[2];       /* default: what the persona starts with */
    unsigned int priv_cur[2];       /* enabled now */
    int          nids;
    char         ids[ST_MAX_IDS][32];   /* identifiers held, by name */
} st_whoami;

int  st_plat_whoami(st_whoami *w, st_err *e);

/* ---- users (SYSUAF), read as the current persona ----

   OpenVMS decides what the persona may see: SYSUAF has no group or world access,
   and $GETUAI allows the caller's own record, its UIC group's with GRPPRV, and
   anyone's with SYSPRV. A refusal comes back as ST_E_NOPRIV with the OS's text. */

/* User flags, as bit numbers. On OpenVMS these are the UAI$_FLAGS bits, mapped one
   by one from the UAI$M_ constants (st_plat_vms.c), never assumed. */
enum {
    ST_UF_DISCTLY, ST_UF_DEFCLI, ST_UF_LOCKPWD, ST_UF_RESTRICTED, ST_UF_DISUSER,
    ST_UF_DISWELCOME, ST_UF_DISNEWMAIL, ST_UF_DISMAIL, ST_UF_GENPWD, ST_UF_PWD_EXPIRED,
    ST_UF_PWD2_EXPIRED, ST_UF_AUDIT, ST_UF_DISREPORT, ST_UF_DISRECONNECT,
    ST_UF_AUTOLOGIN, ST_UF_DISFORCE_PWD_CHANGE, ST_UF_CAPTIVE, ST_UF_DISIMAGE,
    ST_UF_DISPWDDIC, ST_UF_DISPWDHIS, ST_UF_DEFCLSVAL, ST_UF_EXTAUTH,
    ST_UF_MIGRATEPWD, ST_UF_VMSAUTH, ST_UF_DISPWDSYNCH, ST_UF_PWDMIX,
    ST_UF_COUNT
};

/* Access restrictions by kind of login, as AUTHORIZE shows them. */
enum { ST_ACC_NETWORK, ST_ACC_BATCH, ST_ACC_LOCAL, ST_ACC_DIALUP, ST_ACC_REMOTE, ST_ACC_COUNT };

/* Quotas and limits, in AUTHORIZE's units. ST_Q_CPU is in 10 ms ticks, 0 = none. */
enum {
    ST_Q_PRIO, ST_Q_QUEPRIO, ST_Q_MAXJOBS, ST_Q_MAXACCTJOBS, ST_Q_MAXDETACH, ST_Q_PRCLM,
    ST_Q_BIOLM, ST_Q_DIOLM, ST_Q_ASTLM, ST_Q_TQELM, ST_Q_ENQLM, ST_Q_FILLM, ST_Q_SHRFILLM,
    ST_Q_BYTLM, ST_Q_PBYTLM, ST_Q_JTQUOTA, ST_Q_WSDEF, ST_Q_WSQUO, ST_Q_WSEXTENT,
    ST_Q_PGFLQUO, ST_Q_CPU,
    ST_Q_COUNT
};

typedef struct {
    char          username[13];
    char          owner[32];
    char          account[9];
    unsigned int  uic;                 /* group << 16 | member */
    unsigned int  flags;               /* 1 << ST_UF_* */
    char          cli[32], clitables[32];
    char          defdev[32], defdir[64], lgicmd[64];
    /* Times in seconds since 1970-01-01 UTC; 0 = none or never. */
    long long     expiration;
    long long     last_login_i, last_login_n;   /* interactive, non-interactive */
    long long     pwd_date, pwd2_date;          /* -1: pre-expired */
    long long     pwd_lifetime;                 /* seconds; 0 = none */
    int           pwd_minimum;
    int           login_fails;
    unsigned int  secondary_days;      /* bit 0 Monday .. bit 6 Sunday */
    /* bit h set: no access in hour h (0-23), on primary and on secondary days */
    unsigned int  access_p[ST_ACC_COUNT], access_s[ST_ACC_COUNT];
    unsigned int  priv_auth[2], priv_def[2];
    unsigned long quota[ST_Q_COUNT];
} st_user;

/* Calls fn with each username in SYSUAF order (alphabetical), starting after `after`
   ("" for the start), until fn returns nonzero or the file ends. */
typedef int (*st_name_cb)(const char *username, void *ctx);
int st_plat_user_enum(const char *after, st_name_cb fn, void *ctx, st_err *e);
int st_plat_user_get(const char *username, st_user *u, st_err *e);

/* ---- rights identifiers (RIGHTSLIST), read as the current persona ---- */

/* Identifier attributes, as bit numbers (KGB$M_* on OpenVMS, mapped one by one). */
enum {
    ST_IA_RESOURCE, ST_IA_DYNAMIC, ST_IA_NOACCESS, ST_IA_SUBSYSTEM, ST_IA_IMPERSONATE,
    ST_IA_HOLDER_HIDDEN, ST_IA_NAME_HIDDEN,
    ST_IA_COUNT
};

#define ST_IDENT_GENERAL 0x80000000u   /* value bit 31: general; clear: a UIC */

typedef struct {
    char         name[32];     /* "" when the OS gave none (a holder with no name) */
    unsigned int value;        /* the identifier, or for a holder its UIC */
    unsigned int attrib;       /* 1 << ST_IA_* */
} st_ident;

typedef int (*st_ident_cb)(const st_ident *id, void *ctx);
/* Every identifier, general and UIC, in the database's own order. */
int st_plat_ident_enum(st_ident_cb fn, void *ctx, st_err *e);
int st_plat_ident_get(const char *name, st_ident *id, st_err *e);
/* The identifiers the holder with this UIC holds; attrib is the holding's. */
int st_plat_ident_held(unsigned int uic, st_ident_cb fn, void *ctx, st_err *e);
/* The holders of an identifier: value is the holder's UIC, name its UIC identifier
   (normally the username), attrib the holding's. */
int st_plat_ident_holders(unsigned int value, st_ident_cb fn, void *ctx, st_err *e);

/* ---- changes (Phase 3), as the current persona ----

   OpenVMS decides who may change what (D2): $SETUAI needs SYSPRV (or GRPPRV within
   the group); the rights database needs write access to RIGHTSLIST. Every call
   either changes everything it was given or reports why not. */

/* Which members of st_user_change apply. */
enum {
    ST_UC_OWNER = 1u << 0, ST_UC_ACCOUNT = 1u << 1, ST_UC_CLI = 1u << 2,
    ST_UC_CLITABLES = 1u << 3, ST_UC_DEFDEV = 1u << 4, ST_UC_DEFDIR = 1u << 5,
    ST_UC_LGICMD = 1u << 6, ST_UC_FLAGS = 1u << 7, ST_UC_EXPIRATION = 1u << 8,
    ST_UC_PWD_LIFETIME = 1u << 9, ST_UC_PWD_MINIMUM = 1u << 10,
    ST_UC_DAYS = 1u << 11, ST_UC_ACCESS = 1u << 12, ST_UC_PRIV_AUTH = 1u << 13,
    ST_UC_PRIV_DEF = 1u << 14, ST_UC_QUOTAS = 1u << 15
};

typedef struct {
    unsigned int  fields;                   /* ST_UC_* */
    char          owner[32], account[9], cli[32], clitables[32];
    char          defdev[32], defdir[64], lgicmd[64];
    unsigned int  flags;                    /* the whole new set, 1 << ST_UF_* */
    long long     expiration;               /* seconds since 1970 UTC; 0 = none */
    long long     pwd_lifetime;             /* seconds; 0 = none */
    int           pwd_minimum;
    unsigned int  secondary_days;
    unsigned int  access_p[ST_ACC_COUNT], access_s[ST_ACC_COUNT];
    unsigned int  priv_auth[2], priv_def[2];
    unsigned int  quota_mask;               /* 1 << ST_Q_*: which quotas change */
    unsigned long quota[ST_Q_COUNT];
} st_user_change;

int st_plat_user_modify(const char *username, const st_user_change *c, st_err *e);

/* An administrator sets a password ($SETUAI): the system hashes it and applies the
   account's minimum length. pre_expired: the user must change it at next login. */
int st_plat_user_set_password(const char *username, const char *password, int pre_expired,
                              st_err *e);

/* The longest password the system takes: UAI$C_MAX_PWD_LENGTH from the headers the
   image was built with, 64 on x86-64 and 32 on IA64. $HASH_PASSWORD hashes any length
   (NOTES.md), so the service checks new passwords against this itself. */
int st_plat_password_max(void);

/* A user changes their own password ($ACM CHANGE_PASSWORD), after the caller has
   checked the current one with st_plat_authenticate: a failed change is charged to
   the account, not the client (PHASE3.md). Returns ST_AUTH_OK, ST_AUTH_FAILED (the
   system refused the new password; e->text says why, for the user), or
   ST_AUTH_ERROR. Runs as the service, with no persona. */
int st_plat_change_password(const char *username, const char *current, const char *newpw,
                            const char *client, st_err *e);

/* Rights database. value 0 to st_plat_ident_add: OpenVMS chooses. */
int st_plat_ident_add(const char *name, unsigned int value, unsigned int attrib,
                      st_ident *out, st_err *e);
/* new_name NULL or "": keep the name. */
int st_plat_ident_modify(unsigned int value, const char *new_name, unsigned int set,
                         unsigned int clear, st_err *e);
int st_plat_ident_remove(unsigned int value, st_err *e);
int st_plat_holder_add(unsigned int value, unsigned int uic, unsigned int attrib, st_err *e);
int st_plat_holder_modify(unsigned int value, unsigned int uic, unsigned int set,
                          unsigned int clear, st_err *e);
int st_plat_holder_remove(unsigned int value, unsigned int uic, st_err *e);

/* ---- the system at a glance (the dashboard), read as the current persona ----

   What vms-fastfetch shows, from the same system services: $GETSYI, $GETRMI,
   $DEVICE_SCAN with $GETDVI, a wildcard $GETJPI and a wildcard $GETQUI. Nothing here
   needs privilege, but a process scan sees only what the persona may see; the rest
   is counted as hidden. */
#define ST_MAX_DISKS 32
#define ST_MAX_SESSIONS 64

typedef struct {
    char               device[32];        /* "DKA0:" */
    char               label[16];         /* volume label */
    char               logical_volume[32];/* "DISK$X86SYS" */
    char               filesystem[8];     /* "ODS-5" */
    unsigned long long total, free;       /* bytes */
    int                system_disk;
} st_disk;

typedef struct {
    char               username[13];
    unsigned int       sessions;          /* interactive processes with no owner */
} st_session_count;

typedef struct {
    char               node[16];          /* SYI$_NODENAME */
    char               version[16];       /* SYI$_VERSION, "E9.2-4" */
    char               arch[16];          /* SYI$_ARCH_NAME */
    char               hardware[64];      /* SYI$_HW_NAME */
    int                virtual_machine;   /* SYI$_VIRTUAL_MACHINE */
    long long          boot_time;         /* seconds since 1970 UTC */
    unsigned int       cpus_active, cpus_available;
    /* Idle ticks summed over all CPUs, 100 a second per CPU (RMI$_CPUIDLE), and when
       they were read: two readings give the busy share between them. */
    unsigned long long cpu_idle_ticks;
    long long          sampled_at_ms;     /* milliseconds since 1970 UTC */
    unsigned int       load_current, load_computable, load_computable_out;
    unsigned long long mem_total, mem_free, mem_modified;     /* bytes */
    unsigned long long page_total, page_used;                 /* bytes: page + swap files */
    int                ndisks;
    st_disk            disks[ST_MAX_DISKS];                   /* system disk first */
    unsigned int       processes, processes_hidden;
    int                nsessions;
    st_session_count   sessions[ST_MAX_SESSIONS];
    unsigned int       queues, queues_batch, queues_output, queues_stopped;
    unsigned int       jobs_executing, jobs_pending, jobs_holding, jobs_timed;
    int                cluster_member;
    unsigned int       cluster_nodes, cluster_votes, cluster_quorum;
} st_system;

/* Fills what it can; a part that fails is left zero. -1 only if nothing could be read. */
int st_plat_system(st_system *s, st_err *e);

/* ---- creating and deleting users (Phase 4, D6), as the current persona ----

   As AUTHORIZE ADD, COPY and REMOVE do (PHASE4.md): a create copies a template record
   (DEFAULT, or the user being copied), and a delete also removes the user's UIC
   identifier and holdings. OpenVMS requires write access to SYSUAF (SYSPRV). */
typedef struct {
    char           username[13];
    char           template_user[13];   /* "DEFAULT" for a new user; else the user copied */
    unsigned int   uic;
    const char    *password;            /* Latin-1; the caller scrubs it */
    int            pre_expired;
    int            copy_identifiers;    /* also grant what the template user holds */
    int            create_directory;    /* create the default directory, owned by the user */
    st_user_change more;                /* further fields, applied as a modify would */
    char           warning[160];        /* out: a step that failed after the user was made */
} st_user_new;

/* 0, or -1 with nothing left behind (a failure after the record was written undoes
   what was added). Refuses (ST_E_CONFLICT) a username, identifier name or UIC already
   in the rights database. A failed directory creation is not undone: the user
   exists, and warning says why the directory does not. */
int st_plat_user_create(st_user_new *n, st_err *e);
int st_plat_user_delete(const char *username, st_err *e);

/* The service's own account (STEWARD), read at start-up. */
const char *st_plat_service_account(void);
/* The image Steward runs as, name and type upper case (st_proc_image_name): a pool
   worker busy with a request is reported under the requester's username, but its
   image does not change (NOTES.md, Phase 8b), so a stop refuses this image too. */
const char *st_plat_service_image(void);
/* SYSGEN's MAXSYSGROUP: UIC groups up to it are system groups (8 by default, so
   [1,*] to [10,*] octal). Their processes are never stopped through Steward (Phase
   8b: OPCOM was, in the browser check). */
unsigned int st_plat_max_sys_group(void);

/* ---- access history (Phase 6, D13), read as the current persona ----

   Who reached the system, when, from where and how, merged from accounting, the
   security audit journal, OpenSSH's logs, Steward's own audit log and the live
   process list. OpenVMS decides, source by source, what the viewer may read. */
enum { ST_SRC_ACCOUNTING, ST_SRC_AUDIT, ST_SRC_SSH, ST_SRC_STEWARD, ST_SRC_LIVE, ST_SRC_COUNT };
enum { ST_AE_SESSION, ST_AE_FAILURE, ST_AE_BREAKIN, ST_AE_CONNECTED };

typedef struct {
    long long    start, end;      /* seconds since 1970 UTC; end 0: none (a failure) or not yet */
    int          kind;            /* ST_AE_* */
    int          source;          /* ST_SRC_*: where it came from (the first, when merged) */
    char         user[33];        /* as the source has it */
    char         route[24];       /* "SSH", "TELNET", "DECnet", "LAT", "local", "batch", "network", "Steward" */
    char         from[64];        /* the client: address, node or host */
    char         terminal[24];
    char         detail[128];     /* e.g. "publickey ED25519", "queue SYS$BATCH", a status message */
    unsigned int pid;
} st_access_event;

typedef int (*st_access_cb)(const st_access_event *ev, void *ctx);

/* Calls fn for the events overlapping [since, until], in no particular order.
   src_cond[ST_SRC_COUNT] gets each source's outcome: 0 read, else the condition that
   refused or failed it (and its text in src_text). src_partial[] is 1 for a source
   that was read but not to the end: the SSH logs stop at a time budget, since a node
   can hold tens of thousands (NOTES.md). Returns 0 unless nothing at all could be
   read. */
int st_plat_access(long long since, long long until, st_access_cb fn, void *ctx,
                   unsigned int src_cond[ST_SRC_COUNT], char src_text[ST_SRC_COUNT][96],
                   int src_partial[ST_SRC_COUNT], st_err *e);

/* ---- crypto and time ---- */
int  st_plat_random(void *p, size_t n);
void st_plat_sha256(const void *p, size_t n, unsigned char out[32]);
long long st_plat_time(void);       /* seconds since 1970-01-01 UTC */

/* ---- session store, shared by every process in the pool ---- */
typedef struct {
    unsigned char key[32];          /* SHA-256 of the cookie's token */
    char          username[13];
    long long     created;
    long long     last_seen;
    unsigned char csrf[32];
    char          client[46];
    unsigned int  priv_enable[2];   /* authorized privileges the user switched on (D9) */
} st_session;

int  st_plat_session_put(const st_session *s, st_err *e);          /* insert or replace */
/* 1 found, 0 not found, -1 error */
int  st_plat_session_get(const unsigned char key[32], st_session *s, st_err *e);
int  st_plat_session_delete(const unsigned char key[32], st_err *e);
/* Remove sessions created before created_before or last used before seen_before.
   Called at sign-in, so expired records do not accumulate. */
void st_plat_session_purge(long long created_before, long long seen_before);

/* ---- logical names (Phase 7, D14), as the current persona ---- */

/* The names in a table matching a SHOW LOGICAL pattern, as SHOW LOGICAL/FULL lists
   them for the viewer: in a short-lived detached process created under the persona
   (D14), so OpenVMS decides what is shown. The table has passed st_valid_lnm_table.
   A table that is a search list (e.g. LNM$GROUP, LNM$SYSTEM) gives every table it
   names. privs: the privileges switched on in the session (D9), comma-separated
   names, or "-": the helper is a fresh login, with only the account's defaults, and
   switches these on as the user could at a terminal. On failure e has OpenVMS's
   condition: IVLOGTAB (no such table, or not the viewer's to read), a timeout. */
int st_plat_lnm_list(const char *table, const char *pattern, const char *privs,
                     st_lnm_cb fn, void *ctx, st_err *e);

/* One name, in-process ($TRNLNM), every equivalence. The table must be a real
   shareable table (a table in LNM$SYSTEM_DIRECTORY, never the directory itself,
   never a search list, never a process or job table: st_valid_lnm_table), or LNM$GROUP, which means the
   *viewer's* group table. mode: -1 for the outermost definition (as SHOW LOGICAL
   shows it), or ST_LNM_EXEC to _USER for the one at exactly that mode. table_out
   gets the table it was found in. Returns 1 if found, 0 if not (e->kind
   ST_E_NOTFOUND), -1 on error. */
int st_plat_lnm_get(const char *table, const char *name, int mode, st_lnm *out,
                    char table_out[ST_LNM_TABLE_MAX + 1], st_err *e);

/* ---- logical names: changes (Phase 7b, D15), in-process as the current persona ----
   The table, for all three, is a real shareable table as for st_plat_lnm_get, named
   in full (the caller turns LNM$GROUP into the viewer's group table: under a persona
   OpenVMS would take the service's). */

/* The modes <name> has in <table>: bit (1 << mode) for each of kernel (0) to user
   (3), 0 for none. SHOW LOGICAL lists only the outermost. -1 on error. */
int st_plat_lnm_modes(const char *table, const char *name, st_err *e);

/* Define d ($CRELNM): a new name, or the one at d->mode replaced (the caller has
   checked d->replace). Supervisor and executive mode need SYSNAM switched on:
   without it this fails with ST_E_NOPRIV (NOSYSNAM) and asks OpenVMS nothing, since
   OpenVMS would quietly define the name at user mode instead (NOTES.md). Returns 1
   defined, 2 if OpenVMS said SUPERSEDE (which it also says when no_alias removed
   the name at an outer mode only), -1 on error. */
int st_plat_lnm_define(const st_lnm_def *d, st_err *e);

/* Deassign <name> at <mode> and every outer mode, as DEASSIGN does ($DELLNM). The same
   SYSNAM rule. Returns 0, or -1 (NOLOGNAM: ST_E_NOTFOUND). */
int st_plat_lnm_deassign(const char *table, const char *name, int mode, st_err *e);

/* ---- processes (Phase 8, D16), as the current persona ----

   OpenVMS decides which processes the persona may see: its own, its UIC group's with
   GROUP, all with WORLD (probe_jpi, PHASE8.md). The process serving the request is
   never given: under the persona it reports the viewer's username and UIC. */

typedef struct {
    unsigned int pid;
    char         name[16];          /* process name */
    char         username[13];
    unsigned int uic;
    int          state;             /* JPI$_STATE: st_proc_state_name */
    int          pri, prib;         /* current and base priority */
    int          mode;              /* JPI$_MODE: st_proc_kind */
    int          subprocess;        /* it has an owner */
    char         terminal[16];      /* "" for none */
    char         image[256];        /* the image running, "" for none */
    unsigned int cputim;            /* CPU time, 10 ms ticks */
    unsigned int dirio, bufio, pageflts;
    long long    login;             /* login or creation, seconds since 1970 */
} st_proc;

/* A quota: its limit and what is left of it, as SHOW PROCESS/QUOTAS shows them. */
enum { ST_PQ_AST, ST_PQ_BIO, ST_PQ_DIO, ST_PQ_FIL, ST_PQ_PRC, ST_PQ_TQ, ST_PQ_ENQ,
       ST_PQ_BYT, ST_PQ_PGFL, ST_PQ_COUNT };

typedef struct {
    st_proc      p;
    unsigned int owner;             /* the owner's PID, for a subprocess; else 0 */
    unsigned int master;            /* the job's master process */
    unsigned int subprocesses;
    unsigned int wssize;            /* working set size, pagelets */
    unsigned int wspages;           /* pages in the working set */
    unsigned int priv_cur[2], priv_auth[2];
    int          nids;
    char         ids[ST_MAX_IDS][32];  /* rights held, general identifiers, by name */
    unsigned int quota[ST_PQ_COUNT];   /* limits */
    unsigned int left[ST_PQ_COUNT];    /* remaining */
} st_proc_detail;

typedef int (*st_proc_cb)(const st_proc *p, void *ctx);   /* nonzero stops the walk */

/* Every process the persona may see, in the order OpenVMS walks them. */
int st_plat_proc_enum(st_proc_cb fn, void *ctx, st_err *e);
/* One process: ST_E_NOPRIV if the persona may not see it, ST_E_NOTFOUND if there is
   none (or it is the one serving the request). */
int st_plat_proc_get(unsigned int pid, st_proc_detail *d, st_err *e);
/* Stop it, as STOP/ID ($DELPRC, Phase 8b): OpenVMS checks the persona (its own UIC,
   GROUP, WORLD). Asynchronous: the process may still be there when this returns. The
   process serving the request is ST_E_NOTFOUND, as for st_plat_proc_get. The caller
   refuses the service account's processes. */
int st_plat_proc_stop(unsigned int pid, st_err *e);

/* ---- queues (Phase 9, D17), as the current persona ----

   $GETQUI asks the queue manager, which judges the persona: every queue is listed,
   and a job the viewer may not read comes back with only its entry and status, the
   inaccessible bit set (probe_qui, PHASE9.md). */

typedef struct {
    char         name[32];
    int          batch;             /* batch, or output (print, server, terminal) */
    int          generic;
    unsigned int status;            /* QUI$_QUEUE_STATUS: st_queue_status_names */
    char         node[16];          /* /ON=node::, "" for none */
    char         description[256];
    unsigned int job_limit;
    unsigned int executing, pending, holding, timed;
} st_queue;

typedef struct {
    unsigned int entry;
    char         name[40];          /* "" if inaccessible */
    char         username[13];      /* "" if inaccessible */
    unsigned int status;            /* QUI$_JOB_STATUS: st_job_status_names */
    long long    submitted;         /* seconds since 1970, 0 if not given */
    char         queue[32];
} st_job;

#define ST_JOB_FILES 16
typedef struct {
    st_job       j;
    long long    after;             /* /AFTER, 0 for none */
    unsigned int priority;
    char         account[9];
    unsigned int uic;
    char         log[256];          /* the log file, "" for none */
    int          nfiles;
    char         files[ST_JOB_FILES][256];
} st_job_detail;

typedef int (*st_queue_cb)(const st_queue *q, void *ctx);   /* nonzero stops */
typedef int (*st_job_cb)(const st_job *j, void *ctx);

/* Every queue, as SHOW QUEUE lists them. */
int st_plat_queue_enum(st_queue_cb fn, void *ctx, st_err *e);
/* One queue by its name (st_valid_queue_name), then each of its jobs in turn, as SHOW
   QUEUE/ALL. ST_E_NOTFOUND if there is no such queue. */
int st_plat_queue_get(const char *name, st_queue *q, st_job_cb fn, void *ctx, st_err *e);
/* One job by entry number, as SHOW ENTRY/FULL. ST_E_NOPRIV if it is the viewer's to
   see listed but not to read (inaccessible), ST_E_NOTFOUND if there is none. */
int st_plat_job_get(unsigned int entry, st_job_detail *d, st_err *e);

/* ---- queue changes (Phase 9b), $SNDJBC as the current persona: the queue manager
   judges the persona (probe_sndjbc). A refusal is ST_E_NOPRIV (JBC NOPRIV); a job
   that is executing, for a hold, is ST_E_CONFLICT (JBC EXECUTING). */
enum { ST_JOB_HOLD, ST_JOB_RELEASE, ST_JOB_DELETE };
int st_plat_job_change(unsigned int entry, int op, st_err *e);
enum { ST_QUEUE_STOP, ST_QUEUE_START };
int st_plat_queue_change(const char *name, int op, st_err *e);
/* The queues Steward's start-up depends on: SYS$BATCH, what it names in the system
   table (followed in turn), and the execution queues it feeds. Up to max names into
   names; returns how many, or -1 if it cannot tell (the queue manager did not answer,
   or there were more than fit): the caller then refuses every queue stop. Read under
   the request's persona: harmless, every user may see every queue (probe_qui). */
int st_plat_startup_queues(char names[][32], int max);

/* ---- system parameters (Phase 10, D18), as the current persona ----

   Every parameter as SYSGEN SHOW/ALL prints it, run in the D14 helper process (the
   viewer) by the fixed procedure STEWARD_SYSGEN.COM, and parsed by st_sysgen.c.
   privs as for st_plat_lnm_list. */
int st_plat_sysgen_list(const char *privs, st_param_cb fn, void *ctx, st_err *e);

/* ---- licences (Phase 11, D19), as the current persona ----

   SHOW LICENSE/FULL, SHOW LICENSE/UNIT_REQUIREMENTS and LICENSE LIST/FULL, run in the
   D14 helper process (the viewer) by the fixed procedure STEWARD_LICENSE.COM, into p
   (st_license_init'ed by the caller). A part OpenVMS refused is not an error: its
   condition is in p->status and its $GETMSG text in text[part]. privs as for
   st_plat_lnm_list. */
int st_plat_license_list(const char *privs, st_license_parser *p, char text[ST_LIC_PARTS][256], st_err *e);

/* ---- installed products (Phase 12, D20), as the current persona ----

   PRODUCT SHOW PRODUCT/FULL and PRODUCT SHOW HISTORY/FULL, run in the D14 helper
   process (the viewer) by the fixed procedure STEWARD_PRODUCT.COM, into p
   (st_product_init'ed by the caller). PRODUCT needs the account authorized for SYSLCK
   (it switches it on itself): a part OpenVMS refused is not an error, its condition is
   in p->status and PRODUCT's own message in text[part].
   privs as for st_plat_lnm_list. */
int st_plat_product_list(const char *privs, st_product_parser *p, char text[ST_PROD_PARTS][256], st_err *e);

/* VMSINSTAL's history, SYS$UPDATE:VMSINSTAL.HISTORY, read in-process as the persona:
   fn for each run, oldest first, until it returns nonzero. *cond is 0 when the file
   was read, else the condition that refused or failed it, with its text. */
typedef int (*st_vmsinstal_cb)(const st_vmsinstal *v, void *ctx);
int st_plat_vmsinstal(st_vmsinstal_cb fn, void *ctx, unsigned int *cond, char text[256], st_err *e);

/* ---- monitoring (Phase 13, D21), as the current persona ----

   One reading of the counters MONITOR shows, from $GETRMI and $GETDVI: open to anyone
   (probe_rmi, NOTES.md). Counters run from boot, so rates come from two readings; that
   arithmetic is the browser's (D21). The process list is st_plat_proc_enum's. */
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

/* Fills what it can; an item OpenVMS refuses is left zero. -1 only if nothing could be
   read. */
int st_plat_monitor(st_monitor *m, st_err *e);

/* ---- audit and diagnostics ---- */
void st_plat_audit(const char *line);    /* one record; the platform adds a timestamp */
void st_plat_log(const char *line);      /* operational log (SYS$ERROR / stderr) */

#endif
