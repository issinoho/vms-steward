/* st_http.c - CGI/FastCGI request and response model, no I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_fcgi.h"
#include "st_http.h"

typedef struct { st_request *r; char *sp; } collect_ctx;

static int collect(void *ctx, const char *n, size_t nl, const char *v, size_t vl)
{
    collect_ctx *c = ctx;
    st_kv *kv;
    if (c->r->nparams >= ST_REQ_MAX_PARAMS) { c->r->too_many_params = 1; return 1; }
    kv = &c->r->params[c->r->nparams++];
    kv->name = c->sp;
    memcpy(c->sp, n, nl); c->sp += nl; *c->sp++ = '\0';
    kv->value = c->sp;
    memcpy(c->sp, v, vl); c->sp += vl; *c->sp++ = '\0';
    return 0;
}

int st_request_init(st_request *r, const unsigned char *params, size_t plen,
                    const char *body, size_t blen)
{
    collect_ctx c;
    const char *uri, *q;
    size_t n;

    memset(r, 0, sizeof *r);
    /* Each pair stores name and value plus two terminators in no more than the bytes
       of its length prefixes and data, so plen + 1 always suffices. */
    r->store = malloc(plen + 1);
    if (!r->store) return -1;
    c.r = r;
    c.sp = r->store;
    if (st_fcgi_pairs(params, plen, collect, &c)) return -1;

    r->method = st_req_param(r, "REQUEST_METHOD");
    uri = st_req_param(r, "REQUEST_URI");
    if (!r->method || !uri) return -1;
    q = strchr(uri, '?');
    n = q ? (size_t) (q - uri) : strlen(uri);
    if (n >= sizeof r->path) return -1;
    memcpy(r->path, uri, n);
    r->path[n] = '\0';
    r->query = q ? q + 1 : "";
    r->remote_addr = st_req_param(r, "REMOTE_ADDR");
    if (!r->remote_addr) r->remote_addr = "";
    r->body = body;
    r->body_len = blen;
    return 0;
}

void st_request_free(st_request *r)
{
    free(r->store);
    r->store = NULL;
}

const char *st_req_param(const st_request *r, const char *name)
{
    int i;
    for (i = 0; i < r->nparams; i++)
        if (!strcmp(r->params[i].name, name)) return r->params[i].value;
    return NULL;
}

int st_req_cookie(const st_request *r, const char *name, char *out, size_t outlen)
{
    const char *h = st_req_param(r, "HTTP_COOKIE"), *p;
    size_t nl = strlen(name);
    if (!h) return 0;
    for (p = h; *p; ) {
        const char *end;
        size_t vl;
        while (*p == ' ' || *p == ';') p++;
        end = strchr(p, ';');
        if (!end) end = p + strlen(p);
        if ((size_t) (end - p) > nl && !strncmp(p, name, nl) && p[nl] == '=') {
            vl = (size_t) (end - p) - nl - 1;
            while (vl && p[nl + 1 + vl - 1] == ' ') vl--;
            if (vl >= outlen) return 0;
            memcpy(out, p + nl + 1, vl);
            out[vl] = '\0';
            return 1;
        }
        p = end;
    }
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int st_pct_decode(const char *src, size_t n, char *out, size_t outlen, int plus_space)
{
    size_t i, o = 0;
    for (i = 0; i < n; i++) {
        char c = src[i];
        if (c == '%') {
            int hi, lo;
            if (i + 2 >= n) return -1;   /* needs two hex digits after '%' */
            hi = hexval(src[i + 1]); lo = hexval(src[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            c = (char) (hi * 16 + lo);
            if (c == '\0') return -1;
            i += 2;
        } else if (c == '+' && plus_space) c = ' ';
        if (o + 1 >= outlen) return -1;
        out[o++] = c;
    }
    if (o >= outlen) return -1;
    out[o] = '\0';
    return 0;
}

int st_req_query(const st_request *r, const char *name, char *out, size_t outlen)
{
    const char *p = r->query;
    size_t nl = strlen(name);
    while (*p) {
        const char *end = strchr(p, '&'), *eq;
        if (!end) end = p + strlen(p);
        eq = memchr(p, '=', (size_t) (end - p));
        if (eq && (size_t) (eq - p) == nl && !strncmp(p, name, nl))
            return st_pct_decode(eq + 1, (size_t) (end - eq - 1), out, outlen, 1) == 0;
        p = *end ? end + 1 : end;
    }
    return 0;
}

void st_resp_init(st_response *r)
{
    memset(r, 0, sizeof *r);
    r->status = 200;
    st_buf_init(&r->headers, 8192);
    st_buf_init(&r->body, 4 * 1024 * 1024);
}

void st_resp_free(st_response *r)
{
    st_buf_free(&r->headers);
    st_buf_free(&r->body);
}

void st_resp_header(st_response *r, const char *name, const char *value)
{
    /* Header values come from our own code, never from the request; refuse CR/LF
       anyway rather than allow a split response. */
    if (strpbrk(name, "\r\n:") || strpbrk(value, "\r\n")) return;
    st_buf_puts(&r->headers, name);
    st_buf_puts(&r->headers, ": ");
    st_buf_puts(&r->headers, value);
    st_buf_puts(&r->headers, "\r\n");
}

void st_resp_json(st_response *r, int status, st_jw *w)
{
    r->status = status;
    r->content_type = "application/json";
    st_buf_reset(&r->body);
    st_jw_init(w, &r->body);
}

void st_resp_problem(st_response *r, int status, const char *slug, const char *title,
                     const char *detail, unsigned int cond, const char *cond_text)
{
    st_jw w;
    char type[128];
    st_resp_json(r, status, &w);
    r->content_type = "application/problem+json";
    strcpy(type, "/api/v1/problems/");
    strncat(type, slug, sizeof type - strlen(type) - 1);
    st_jw_obj(&w);
    st_jw_kstr(&w, "type", type);
    st_jw_kstr(&w, "title", title);
    st_jw_kint(&w, "status", status);
    if (detail && *detail) st_jw_kstr(&w, "detail", detail);
    if (cond) {
        char hex[16];
        sprintf(hex, "%%X%08X", cond);
        st_jw_kstr(&w, "vms_status", hex);
        if (cond_text && *cond_text) st_jw_kstr(&w, "vms_message", cond_text);
    }
    st_jw_obj_end(&w);
}

const char *st_status_text(int s)
{
    switch (s) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default:  return "Status";
    }
}

int st_resp_serialize(st_response *r, st_buf *out)
{
    if (!st_buf_ok(&r->body) || !st_buf_ok(&r->headers)) {
        /* The response outgrew its limits: say so rather than send half of it. */
        st_resp_free(r);
        st_resp_init(r);
        st_resp_problem(r, 500, "response-too-large", "Response too large", NULL, 0, NULL);
    }
    st_buf_printf(out, "Status: %d %s\r\n", r->status, st_status_text(r->status));
    if (r->status != 204) {
        st_buf_printf(out, "Content-Type: %s; charset=utf-8\r\n",
                      r->content_type ? r->content_type : "application/json");
        st_buf_printf(out, "Content-Length: %lu\r\n", (unsigned long) r->body.len);
    }
    st_buf_puts(out, "Cache-Control: no-store\r\n");
    st_buf_puts(out, "X-Content-Type-Options: nosniff\r\n");
    st_buf_append(out, r->headers.data, r->headers.len);
    st_buf_puts(out, "\r\n");
    if (r->status != 204) st_buf_append(out, r->body.data, r->body.len);
    return st_buf_ok(out);
}
