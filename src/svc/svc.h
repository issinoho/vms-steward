/* svc.h - endpoint handlers. Each runs after st_app_handle has applied the checks
   its route asks for, and under the caller's persona unless the route says not. */
#ifndef SVC_H
#define SVC_H

struct st_ctx;

void svc_health(struct st_ctx *c);
void svc_session_login(struct st_ctx *c);
void svc_session_get(struct st_ctx *c);
void svc_session_logout(struct st_ctx *c);

/* The name of OpenVMS privilege bit n (0-63), or NULL. */
const char *svc_priv_name(int bit);

#endif
