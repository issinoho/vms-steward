/* st_fcgi.c - FastCGI responder protocol, no I/O. */
#include <string.h>
#include "st_fcgi.h"

long st_fcgi_parse(const unsigned char *buf, size_t avail, st_fcgi_rec *rec)
{
    size_t clen, total;
    if (avail < ST_FCGI_HEADER_LEN) return 0;
    if (buf[0] != ST_FCGI_VERSION_1) return -1;
    clen = ((size_t) buf[4] << 8) | buf[5];
    total = ST_FCGI_HEADER_LEN + clen + buf[6];
    if (avail < total) return 0;
    rec->type = buf[1];
    rec->id = ((unsigned int) buf[2] << 8) | buf[3];
    rec->content = buf + ST_FCGI_HEADER_LEN;
    rec->len = clen;
    return (long) total;
}

/* A pair length is one byte below 128, otherwise four bytes with the top bit set. */
static int get_len(const unsigned char **p, const unsigned char *end, size_t *out)
{
    if (*p >= end) return -1;
    if (!(**p & 0x80)) { *out = *(*p)++; return 0; }
    if (end - *p < 4) return -1;
    *out = ((size_t) ((*p)[0] & 0x7F) << 24) | ((size_t) (*p)[1] << 16) |
           ((size_t) (*p)[2] << 8) | (*p)[3];
    *p += 4;
    return 0;
}

int st_fcgi_pairs(const unsigned char *p, size_t len, st_fcgi_pair_cb cb, void *ctx)
{
    const unsigned char *end = p + len;
    while (p < end) {
        size_t nl, vl;
        if (get_len(&p, end, &nl) || get_len(&p, end, &vl)) return -1;
        if (nl > (size_t) (end - p) || vl > (size_t) (end - p) - nl) return -1;
        if (cb(ctx, (const char *) p, nl, (const char *) p + nl, vl)) return 0;
        p += nl + vl;
    }
    return 0;
}

static int put_len(st_buf *out, size_t n)
{
    unsigned char b[4];
    if (n < 128) { b[0] = (unsigned char) n; return st_buf_append(out, b, 1); }
    b[0] = (unsigned char) (((n >> 24) & 0x7F) | 0x80);
    b[1] = (unsigned char) (n >> 16);
    b[2] = (unsigned char) (n >> 8);
    b[3] = (unsigned char) n;
    return st_buf_append(out, b, 4);
}

int st_fcgi_put_pair(st_buf *out, const char *name, const char *val)
{
    size_t nl = strlen(name), vl = strlen(val);
    return put_len(out, nl) && put_len(out, vl) &&
           st_buf_append(out, name, nl) && st_buf_append(out, val, vl);
}

static int header(st_buf *out, int type, unsigned int id, size_t len)
{
    unsigned char h[ST_FCGI_HEADER_LEN];
    h[0] = ST_FCGI_VERSION_1;
    h[1] = (unsigned char) type;
    h[2] = (unsigned char) (id >> 8);
    h[3] = (unsigned char) id;
    h[4] = (unsigned char) (len >> 8);
    h[5] = (unsigned char) len;
    h[6] = 0;   /* no padding: alignment is a recommendation, not a requirement */
    h[7] = 0;
    return st_buf_append(out, h, sizeof h);
}

int st_fcgi_write(st_buf *out, int type, unsigned int id, const void *content, size_t len)
{
    const char *p = content;
    if (len == 0) return header(out, type, id, 0);
    while (len > 0) {
        size_t n = len > 65535 ? 65535 : len;
        if (!header(out, type, id, n) || !st_buf_append(out, p, n)) return 0;
        p += n;
        len -= n;
    }
    return 1;
}

int st_fcgi_end_request(st_buf *out, unsigned int id, unsigned int app_status, int proto)
{
    unsigned char b[8];
    b[0] = (unsigned char) (app_status >> 24);
    b[1] = (unsigned char) (app_status >> 16);
    b[2] = (unsigned char) (app_status >> 8);
    b[3] = (unsigned char) app_status;
    b[4] = (unsigned char) proto;
    b[5] = b[6] = b[7] = 0;
    return st_fcgi_write(out, ST_FCGI_END_REQUEST, id, b, sizeof b);
}

void st_fcgi_conn_init(st_fcgi_conn *c, size_t params_limit, size_t body_limit)
{
    memset(c, 0, sizeof *c);
    st_buf_init(&c->params, params_limit);
    st_buf_init(&c->body, body_limit);
}

void st_fcgi_conn_reset(st_fcgi_conn *c)
{
    c->id = 0;
    c->active = c->keep_conn = c->params_done = c->stdin_done = 0;
    st_buf_reset(&c->params);
    st_buf_reset(&c->body);
}

void st_fcgi_conn_free(st_fcgi_conn *c)
{
    st_buf_free(&c->params);
    st_buf_free(&c->body);
}

typedef struct { st_buf *out; } values_ctx;

static int values_cb(void *ctx, const char *n, size_t nl, const char *v, size_t vl)
{
    st_buf *out = ((values_ctx *) ctx)->out;
    (void) v; (void) vl;
    if (nl == 14 && !memcmp(n, "FCGI_MAX_CONNS", 14)) st_fcgi_put_pair(out, "FCGI_MAX_CONNS", "1");
    if (nl == 13 && !memcmp(n, "FCGI_MAX_REQS", 13)) st_fcgi_put_pair(out, "FCGI_MAX_REQS", "1");
    if (nl == 15 && !memcmp(n, "FCGI_MPXS_CONNS", 15)) st_fcgi_put_pair(out, "FCGI_MPXS_CONNS", "0");
    return 0;
}

int st_fcgi_conn_handle(st_fcgi_conn *c, const st_fcgi_rec *r, st_buf *out)
{
    if (r->id == 0) {   /* management records */
        if (r->type == ST_FCGI_GET_VALUES) {
            st_buf pairs; values_ctx vc;
            st_buf_init(&pairs, 4096);
            vc.out = &pairs;
            st_fcgi_pairs(r->content, r->len, values_cb, &vc);
            st_fcgi_write(out, ST_FCGI_GET_VALUES_RESULT, 0, pairs.data, pairs.len);
            st_buf_free(&pairs);
        } else {
            unsigned char b[8];
            memset(b, 0, sizeof b);
            b[0] = r->type;
            st_fcgi_write(out, ST_FCGI_UNKNOWN_TYPE, 0, b, sizeof b);
        }
        return ST_FCGI_NONE;
    }

    if (r->type == ST_FCGI_BEGIN_REQUEST) {
        int role;
        if (r->len < 8) return ST_FCGI_CLOSE;
        if (c->active && r->id != c->id) {
            st_fcgi_end_request(out, r->id, 0, ST_FCGI_CANT_MPX_CONN);
            return ST_FCGI_NONE;
        }
        role = (r->content[0] << 8) | r->content[1];
        if (role != ST_FCGI_RESPONDER) {
            st_fcgi_end_request(out, r->id, 0, ST_FCGI_UNKNOWN_ROLE);
            return (r->content[2] & ST_FCGI_KEEP_CONN) ? ST_FCGI_NONE : ST_FCGI_CLOSE;
        }
        st_fcgi_conn_reset(c);
        c->id = r->id;
        c->active = 1;
        c->keep_conn = r->content[2] & ST_FCGI_KEEP_CONN;
        return ST_FCGI_NONE;
    }

    if (!c->active || r->id != c->id) return ST_FCGI_NONE;   /* not ours: ignore */

    switch (r->type) {
    case ST_FCGI_PARAMS:
        if (c->params_done) return ST_FCGI_NONE;
        if (r->len == 0) c->params_done = 1;
        else st_buf_append(&c->params, r->content, r->len);   /* overflow noted in buf */
        break;
    case ST_FCGI_STDIN:
        if (c->stdin_done) return ST_FCGI_NONE;
        if (r->len == 0) c->stdin_done = 1;
        else st_buf_append(&c->body, r->content, r->len);
        break;
    case ST_FCGI_ABORT_REQUEST:
        st_fcgi_end_request(out, c->id, 0, ST_FCGI_REQUEST_COMPLETE);
        {
            int keep = c->keep_conn;
            st_fcgi_conn_reset(c);
            return keep ? ST_FCGI_ABORTED : ST_FCGI_CLOSE;
        }
    default:
        return ST_FCGI_NONE;   /* DATA is for the filter role */
    }
    return (c->params_done && c->stdin_done) ? ST_FCGI_READY : ST_FCGI_NONE;
}

int st_fcgi_respond(st_buf *out, unsigned int id, const char *resp, size_t len)
{
    return st_fcgi_write(out, ST_FCGI_STDOUT, id, resp, len) &&
           st_fcgi_write(out, ST_FCGI_STDOUT, id, NULL, 0) &&
           st_fcgi_end_request(out, id, 0, ST_FCGI_REQUEST_COMPLETE);
}
