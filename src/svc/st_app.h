/* st_app.h - request dispatch: routing, sessions, CSRF, personas. */
#ifndef ST_APP_H
#define ST_APP_H

#include "st_http.h"
#include "st_json.h"
#include "st_route.h"
#include "st_platform.h"

#define ST_COOKIE "steward_session"

typedef struct {
    long idle_secs;       /* a session unused this long ends */
    long absolute_secs;   /* and none lasts longer than this */
    int  cookie_secure;   /* 0 only for the plain-HTTP development server */
    /* Reverse proxies whose X-Forwarded-* headers are believed (D7): a comma-separated
       list of addresses and IPv4 CIDR ranges, e.g. "127.0.0.1,172.17.0.0/16".
       Empty: forwarded headers are ignored entirely. */
    const char *trusted_proxies;
} st_app_config;

typedef struct st_ctx {
    const st_request    *req;
    st_response         *resp;
    const st_app_config *cfg;
    st_session           session;     /* valid when has_session */
    int                  has_session;
    char                 args[ST_ROUTE_ARGS][ST_ARG_MAX];
    int                  nargs;
    /* The request as the browser made it, which behind a trusted proxy differs from
       what lighttpd saw (D7). */
    char                 client[46];    /* browser's address */
    char                 scheme[6];     /* "https" or "http" */
    char                 host[256];     /* Host the browser used */
    char                 prefix[128];   /* path the proxy mounts us under, or "" */
} st_ctx;

/* Exposed for unit tests: fill client/scheme/host/prefix from req and the trusted
   proxy list. */
void st_app_origin(st_ctx *c, const char *trusted_proxies);

void st_app_init(const st_app_config *cfg);
/* body_overflow: the FastCGI layer dropped part of the body (over its limit). */
void st_app_handle(const st_request *req, int body_overflow, st_response *resp);

/* For handlers. */
void st_app_error(st_ctx *c, const st_err *e);
/* Parse the JSON body into doc; on failure the 400 response is already set. */
int  st_app_body(st_ctx *c, st_jdoc *doc);
void st_app_audit(st_ctx *c, const char *user, const char *action, const char *target,
                  const char *outcome, const char *detail);
void st_app_set_cookie(st_ctx *c, const char *token_hex, long max_age);

#endif
