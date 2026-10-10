/* st_http.h - CGI/FastCGI request and response model, no I/O. */
#ifndef ST_HTTP_H
#define ST_HTTP_H

#include <stddef.h>
#include "st_buf.h"
#include "st_json.h"

#define ST_REQ_MAX_PARAMS 128

typedef struct { const char *name, *value; } st_kv;

typedef struct {
    st_kv       params[ST_REQ_MAX_PARAMS];
    int         nparams;
    char       *store;          /* NUL-terminated copies of the params */
    const char *method;         /* REQUEST_METHOD */
    char        path[1024];     /* REQUEST_URI up to '?', still percent-encoded */
    const char *query;          /* after '?', or "" */
    const char *remote_addr;
    const char *body;
    size_t      body_len;
    int         too_many_params;
} st_request;

/* Build from a FastCGI PARAMS stream and the STDIN body. Returns 0, or -1 if the
   params are malformed or REQUEST_METHOD/REQUEST_URI are missing. The body is not
   copied: it must outlive the request. */
int  st_request_init(st_request *r, const unsigned char *params, size_t plen,
                     const char *body, size_t blen);
void st_request_free(st_request *r);

const char *st_req_param(const st_request *r, const char *name);
/* An HTTP request header, by its CGI name, e.g. "HTTP_X_STEWARD_CSRF". */
#define st_req_header(r, cgi) st_req_param((r), (cgi))
/* Copy the named cookie's value. Returns 1 if found and it fit. */
int st_req_cookie(const st_request *r, const char *name, char *out, size_t outlen);
/* Copy and percent-decode the named query parameter. Returns 1 if found and valid. */
int st_req_query(const st_request *r, const char *name, char *out, size_t outlen);

/* Percent-decode src[0..n) into out. Refuses %00 and malformed escapes; '+' stays '+'
   (paths), unless plus_space. Returns 0, or -1. */
int st_pct_decode(const char *src, size_t n, char *out, size_t outlen, int plus_space);

typedef struct {
    int    status;
    st_buf headers;   /* extra header lines, each ending CRLF */
    st_buf body;
    const char *content_type;
} st_response;

void st_resp_init(st_response *r);
void st_resp_free(st_response *r);
void st_resp_header(st_response *r, const char *name, const char *value);
/* Start a JSON body: sets the content type and returns a writer on the body. */
void st_resp_json(st_response *r, int status, st_jw *w);
/* RFC 9457 problem details. cond/cond_text describe an OpenVMS condition when there
   is one (cond 0: none). */
void st_resp_problem(st_response *r, int status, const char *slug, const char *title,
                     const char *detail, unsigned int cond, const char *cond_text);
/* "Status:" line, headers, blank line and body, as a CGI response. */
int  st_resp_serialize(st_response *r, st_buf *out);
const char *st_status_text(int status);

#endif
