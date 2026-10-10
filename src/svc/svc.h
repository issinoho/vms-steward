/* svc.h - endpoint handlers. Each runs after st_app_handle has applied the checks
   its route asks for, and under the caller's persona unless the route says not. */
#ifndef SVC_H
#define SVC_H

#include <stddef.h>
#include "st_json.h"

struct st_ctx;

void svc_health(struct st_ctx *c);
void svc_session_login(struct st_ctx *c);
void svc_session_get(struct st_ctx *c);
void svc_session_logout(struct st_ctx *c);
void svc_session_privileges(struct st_ctx *c);

void svc_users_list(struct st_ctx *c);
void svc_user_get(struct st_ctx *c);
void svc_user_identifiers(struct st_ctx *c);

void svc_idents_list(struct st_ctx *c);
void svc_ident_get(struct st_ctx *c);
void svc_ident_holders(struct st_ctx *c);

/* The name of OpenVMS privilege bit n (0-63), or NULL. */
const char *svc_priv_name(int bit);
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
