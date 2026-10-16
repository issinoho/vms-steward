/* svc.h - endpoint handlers. Each runs after st_app_handle has applied the checks
   its route asks for, and under the caller's persona unless the route says not. */
#ifndef SVC_H
#define SVC_H

#include <stddef.h>
#include "st_json.h"
#include "st_platform.h"

struct st_ctx;

void svc_health(struct st_ctx *c);
void svc_session_login(struct st_ctx *c);
void svc_session_get(struct st_ctx *c);
void svc_session_logout(struct st_ctx *c);
void svc_session_privileges(struct st_ctx *c);

void svc_users_list(struct st_ctx *c);
void svc_user_get(struct st_ctx *c);
void svc_user_identifiers(struct st_ctx *c);

/* Phase 3: changes. */
void svc_user_modify(struct st_ctx *c);
void svc_user_set_password(struct st_ctx *c);
void svc_user_grant(struct st_ctx *c);
void svc_user_holding(struct st_ctx *c);
void svc_user_revoke(struct st_ctx *c);
void svc_user_create(struct st_ctx *c);
void svc_user_delete(struct st_ctx *c);
void svc_uic_next(struct st_ctx *c);
void svc_password_change(struct st_ctx *c);
void svc_ident_create(struct st_ctx *c);
void svc_ident_modify(struct st_ctx *c);
void svc_ident_delete(struct st_ctx *c);

void svc_system(struct st_ctx *c);
void svc_access(struct st_ctx *c);
void svc_logical_tables(struct st_ctx *c);
void svc_logicals(struct st_ctx *c);
void svc_logical_get(struct st_ctx *c);
void svc_logical_one(struct st_ctx *c);
void svc_logical_define(struct st_ctx *c);
void svc_logical_deassign(struct st_ctx *c);
void svc_processes(struct st_ctx *c);
void svc_process_get(struct st_ctx *c);
void svc_process_stop(struct st_ctx *c);
void svc_queues(struct st_ctx *c);
void svc_queue_get(struct st_ctx *c);
void svc_job_get(struct st_ctx *c);
void svc_job_hold(struct st_ctx *c);
void svc_job_release(struct st_ctx *c);
void svc_job_delete(struct st_ctx *c);
void svc_queue_stop(struct st_ctx *c);
void svc_queue_start(struct st_ctx *c);
void svc_sysgen(struct st_ctx *c);
void svc_licenses(struct st_ctx *c);
void svc_products(struct st_ctx *c);
void svc_idents_list(struct st_ctx *c);
void svc_ident_get(struct st_ctx *c);
void svc_ident_holders(struct st_ctx *c);

/* The privileges switched on in the session (D9), comma-separated, "-" for none: for a
   D14 helper process, a fresh login with only the account's defaults. */
void svc_session_privs(const struct st_ctx *c, char *out, size_t outlen);
/* The name of OpenVMS privilege bit n (0-63), or NULL. */
const char *svc_priv_name(int bit);
/* Name to bit, case-insensitive; -1 if unknown. */
int svc_priv_bit(const char *name);
int svc_flag_bit(const char *name);     /* ST_UF_* */
int svc_attrib_bit(const char *name);   /* ST_IA_* */
int svc_name_index(const char *const *table, int n, const char *name);
extern const char *const svc_access_names[];   /* ST_ACC_COUNT */
extern const char *const svc_quota_names[];    /* ST_Q_COUNT */
extern const char *const svc_day_names[];      /* 7, Monday first */
/* The user record's ETag: a hash of every field a change can touch (svc_edit.c). */
void svc_user_etag(const st_user *u, char out[40]);
/* key: [names of the privileges set in q] */
void svc_privs_json(st_jw *w, const char *key, const unsigned int q[2]);
/* "[g,m]" in octal, as OpenVMS writes a UIC. */
void svc_uic_text(unsigned int uic, char out[24]);
/* An identifier's value as AUTHORIZE shows it: %Xnnnnnnnn, or [g,m] for a UIC. */
void svc_ident_value_text(unsigned int value, char out[24]);
/* key: [names of the identifier attributes set in attrib] */
void svc_ident_attrib_json(st_jw *w, const char *key, unsigned int attrib);
/* A query parameter: 1 with raw filled, 0 if absent, -1 with the 400 response set
   if present but too long or badly encoded. */
int svc_query(struct st_ctx *c, const char *name, char *raw, size_t rawlen);
/* The list endpoints' common query: filter, after (a cursor), limit. 0, or -1 with
   the 400 response set. after is validated by the caller's rule (username or
   identifier name), given as check. */
int svc_list_query(struct st_ctx *c, char filter[32], char after[32], int *limit,
                   int (*check)(const char *in, char out[32]));

#endif
