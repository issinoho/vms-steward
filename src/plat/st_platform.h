/* st_platform.h - everything Steward needs from the operating system.

   Implemented by plat/vms/ (system services) and plat/stub/ (an in-memory fake for
   Linux tests and front-end work). Keep this free of OpenVMS types: condition values
   travel as plain unsigned ints, together with their message text, and privilege
   masks as two longwords.

   Strings crossing this interface are ISO-8859-1, as OpenVMS stores them. */
#ifndef ST_PLATFORM_H
#define ST_PLATFORM_H

#include <stddef.h>

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
/* Become username for the current request. Fails if a persona is already active:
   that means an earlier request did not end its own, which is a bug. */
int  st_plat_persona_begin(const char *username, st_err *e);
/* Return to the service's own identity. Safe to call when no persona is active. */
void st_plat_persona_end(void);
int  st_plat_persona_active(void);

/* ---- the current persona ---- */
#define ST_MAX_IDS 64
typedef struct {
    char         username[13];
    char         owner[33];
    char         account[9];
    unsigned int uic;               /* group << 16 | member */
    unsigned int priv_auth[2];      /* authorized privileges, quadword */
    unsigned int priv_cur[2];       /* enabled now */
    int          nids;
    char         ids[ST_MAX_IDS][32];   /* identifiers held, by name */
} st_whoami;

int  st_plat_whoami(st_whoami *w, st_err *e);

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
} st_session;

int  st_plat_session_put(const st_session *s, st_err *e);          /* insert or replace */
/* 1 found, 0 not found, -1 error */
int  st_plat_session_get(const unsigned char key[32], st_session *s, st_err *e);
int  st_plat_session_delete(const unsigned char key[32], st_err *e);

/* ---- audit and diagnostics ---- */
void st_plat_audit(const char *line);    /* one record; the platform adds a timestamp */
void st_plat_log(const char *line);      /* operational log (SYS$ERROR / stderr) */

#endif
