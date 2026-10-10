/* st_fcgi.h - FastCGI responder protocol (FastCGI Specification 1.0), no I/O.

   Records are parsed with explicit offsets and byte order, never a packed struct.
   One request at a time per connection: the pool runs one process per port and
   lighttpd sends one request per connection, so multiplexed requests are refused
   with CANT_MPX_CONN, as the specification allows. */
#ifndef ST_FCGI_H
#define ST_FCGI_H

#include <stddef.h>
#include "st_buf.h"

#define ST_FCGI_HEADER_LEN     8
#define ST_FCGI_VERSION_1      1

#define ST_FCGI_BEGIN_REQUEST  1
#define ST_FCGI_ABORT_REQUEST  2
#define ST_FCGI_END_REQUEST    3
#define ST_FCGI_PARAMS         4
#define ST_FCGI_STDIN          5
#define ST_FCGI_STDOUT         6
#define ST_FCGI_STDERR         7
#define ST_FCGI_DATA           8
#define ST_FCGI_GET_VALUES     9
#define ST_FCGI_GET_VALUES_RESULT 10
#define ST_FCGI_UNKNOWN_TYPE   11

#define ST_FCGI_RESPONDER      1
#define ST_FCGI_KEEP_CONN      1

#define ST_FCGI_REQUEST_COMPLETE 0
#define ST_FCGI_CANT_MPX_CONN    1
#define ST_FCGI_OVERLOADED       2
#define ST_FCGI_UNKNOWN_ROLE     3

typedef struct {
    unsigned char        type;
    unsigned int         id;
    const unsigned char *content;
    size_t               len;
} st_fcgi_rec;

/* Parse one record from buf. Returns the bytes it occupies (header, content and
   padding), 0 if more input is needed, or -1 if the version byte is wrong. */
long st_fcgi_parse(const unsigned char *buf, size_t avail, st_fcgi_rec *rec);

/* Walk name-value pairs. The callback returns nonzero to stop. Returns 0, or -1 if a
   length runs past the end. */
typedef int (*st_fcgi_pair_cb)(void *ctx, const char *name, size_t nlen,
                               const char *val, size_t vlen);
int st_fcgi_pairs(const unsigned char *p, size_t len, st_fcgi_pair_cb cb, void *ctx);

int st_fcgi_put_pair(st_buf *out, const char *name, const char *val);
/* One stream record per 65535 bytes; len 0 writes the empty end-of-stream record. */
int st_fcgi_write(st_buf *out, int type, unsigned int id, const void *content, size_t len);
int st_fcgi_end_request(st_buf *out, unsigned int id, unsigned int app_status, int proto);

/* Per-connection request assembly. */
typedef struct {
    unsigned int id;
    int    active, keep_conn, params_done, stdin_done;
    st_buf params;
    st_buf body;
} st_fcgi_conn;

enum { ST_FCGI_NONE = 0, ST_FCGI_READY, ST_FCGI_ABORTED, ST_FCGI_CLOSE };

void st_fcgi_conn_init(st_fcgi_conn *c, size_t params_limit, size_t body_limit);
void st_fcgi_conn_reset(st_fcgi_conn *c);
void st_fcgi_conn_free(st_fcgi_conn *c);
/* Feed one record. Replies the protocol requires (GET_VALUES_RESULT, END_REQUEST
   for refused or aborted requests, UNKNOWN_TYPE) are appended to out. Returns
   ST_FCGI_READY once the active request has its params and all its stdin. */
int st_fcgi_conn_handle(st_fcgi_conn *c, const st_fcgi_rec *r, st_buf *out);
/* Send a complete CGI response (headers, blank line, body) for the active request
   and end it. */
int st_fcgi_respond(st_buf *out, unsigned int id, const char *resp, size_t len);

#endif
