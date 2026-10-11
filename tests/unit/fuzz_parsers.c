/* fuzz_parsers.c - mutation fuzzing of everything that parses untrusted bytes.

   make fuzz  (built with -fsanitize=address,undefined)

   No libFuzzer: the toolchain here may be GCC only. Seeds are valid inputs; each round
   flips, inserts, deletes or duplicates bytes and feeds the result to the JSON
   parser, the FastCGI record/pair parsers and connection state machine, request
   building, cookie and query parsing, and route matching. A crash or sanitizer
   report is the failure; there are no assertions on results. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_buf.h"
#include "st_fcgi.h"
#include "st_json.h"
#include "st_lnm.h"
#include "st_http.h"
#include "st_route.h"

static unsigned long rng = 88172645463325252ul;
static unsigned long next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static size_t mutate(unsigned char *buf, size_t len, size_t cap)
{
    int k, rounds = 1 + (int) (next() % 8);
    for (k = 0; k < rounds; k++) {
        size_t pos = len ? next() % len : 0;
        switch (next() % 6) {
        case 0: if (len) buf[pos] ^= (unsigned char) (1u << (next() % 8)); break;
        case 1: if (len) buf[pos] = (unsigned char) next(); break;
        case 2: if (len < cap) { memmove(buf + pos + 1, buf + pos, len - pos); buf[pos] = (unsigned char) next(); len++; } break;
        case 3: if (len) { memmove(buf + pos, buf + pos + 1, len - pos - 1); len--; } break;
        case 4: { size_t n = next() % 16; if (len + n <= cap && pos + n <= len) { memmove(buf + pos + n, buf + pos, len - pos); len += n; } } break;
        case 5: { static const char t[] = "\"\\{}[],:0e-u\x80\xff%;="; if (len) buf[pos] = (unsigned char) t[next() % (sizeof t - 1)]; } break;
        }
    }
    return len;
}

static const char *json_seeds[] = {
    "{\"username\":\"steward_test\",\"password\":\"p\\u00e9ss\"}",
    "[1,-2.5e3,true,false,null,{\"a\":[[]]},\"\\ud83d\\ude00\"]",
    "{\"flags\":{\"disuser\":true},\"expiration\":null,\"quota\":12345}",
};

static int pair_cb(void *ctx, const char *n, size_t nl, const char *v, size_t vl)
{
    (void) ctx; (void) n; (void) nl; (void) v; (void) vl;
    return 0;
}

static st_buf fcgi_seed(void)
{
    st_buf b, p;
    unsigned char begin[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    st_buf_init(&b, 0);
    st_buf_init(&p, 0);
    st_fcgi_put_pair(&p, "REQUEST_METHOD", "POST");
    st_fcgi_put_pair(&p, "REQUEST_URI", "/api/v1/users/SYSTEM%41?x=1&y=%2F");
    st_fcgi_put_pair(&p, "HTTP_COOKIE", "a=b; steward_session=00ff");
    st_fcgi_write(&b, ST_FCGI_BEGIN_REQUEST, 1, begin, 8);
    st_fcgi_write(&b, ST_FCGI_PARAMS, 1, p.data, p.len);
    st_fcgi_write(&b, ST_FCGI_PARAMS, 1, NULL, 0);
    st_fcgi_write(&b, ST_FCGI_STDIN, 1, "{}", 2);
    st_fcgi_write(&b, ST_FCGI_STDIN, 1, NULL, 0);
    st_buf_free(&p);
    return b;
}

static void run_fcgi(const unsigned char *in, size_t len)
{
    st_fcgi_conn c;
    st_buf out;
    st_fcgi_rec r;
    long used;
    st_fcgi_conn_init(&c, 4096, 4096);
    st_buf_init(&out, 0);
    while (len && (used = st_fcgi_parse(in, len, &r)) > 0) {
        st_fcgi_pairs(r.content, r.len, pair_cb, NULL);
        if (st_fcgi_conn_handle(&c, &r, &out) == ST_FCGI_READY) {
            st_request req;
            char v[64], args[ST_ROUTE_ARGS][ST_ARG_MAX];
            int n;
            if (!st_request_init(&req, (unsigned char *) c.params.data, c.params.len,
                                 c.body.data, c.body.len)) {
                st_req_cookie(&req, "steward_session", v, sizeof v);
                st_req_query(&req, "x", v, sizeof v);
                st_route_match("/api/v1/users/{u}", req.path, args, ST_ROUTE_ARGS, &n);
            }
            st_request_free(&req);
            st_fcgi_conn_reset(&c);
        }
        in += used;
        len -= (size_t) used;
    }
    st_fcgi_conn_free(&c);
    st_buf_free(&out);
}

/* SHOW LOGICAL/FULL output (D14): names and values are anyone's who may define one. */
static const char lnm_seed[] =
    "(LNM$SYSTEM_TABLE)\t[kernel]  [shareable,system]\r\n"
    "\t\t\t[Protection=(RWC,RWC,R,R)]  [Owner=[SYSTEM]]\r\n"
    "  \"SYS$SYSROOT\" [exec] = \"X86VMS$DKA0:[SYS0.]\" [concealed,terminal]\r\n"
    "\t= \"SYS$COMMON:\"\r\n"
    "  \"MOTD\" [exec,no_alias] = \"Say \"\"hi\"\"\"\r\n%SYSTEM-F-NOPRIV, x\r\n";

static int lnm_cb(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    (void) ctx;
    return (int) (strlen(t->name) + strlen(n->name)) < 0;
}

static void run_lnm(const unsigned char *in, size_t len)
{
    st_lnm_parser p;
    size_t start = 0, i;
    st_lnm_parse_init(&p, lnm_cb, NULL);
    for (i = 0; i <= len; i++)
        if (i == len || in[i] == '\n') {
            /* each line in a buffer of exactly its length, so ASan sees any read past it */
            char *line = malloc(i - start ? i - start : 1);
            if (!line) return;
            memcpy(line, in + start, i - start);
            st_lnm_parse_line(&p, line, i - start);
            free(line);
            start = i + 1;
        }
    st_lnm_parse_end(&p);
}

int main(int argc, char **argv)
{
    long i, rounds = argc > 1 ? atol(argv[1]) : 100000;
    static unsigned char buf[8192];
    st_buf seed = fcgi_seed();

    for (i = 0; i < rounds; i++) {
        size_t len;
        st_jdoc d;
        char err[80];
        if (i % 3 == 2) {
            len = sizeof lnm_seed - 1;
            memcpy(buf, lnm_seed, len);
            len = mutate(buf, len, sizeof buf);
            run_lnm(buf, len);
        } else if (i % 2 == 0) {
            const char *s = json_seeds[next() % (sizeof json_seeds / sizeof json_seeds[0])];
            len = strlen(s);
            memcpy(buf, s, len);
            len = mutate(buf, len, sizeof buf);
            if (!st_json_parse(&d, (char *) buf, len, err, sizeof err)) {
                st_buf w; st_jw jw;
                char l1[64];
                const char *u = st_json_get_str(d.root, "username");
                if (u) st_json_latin1(u, strlen(u), l1, sizeof l1);
                st_buf_init(&w, 0);
                st_jw_init(&jw, &w);
                if (u) st_jw_str(&jw, u);
                st_buf_free(&w);
                st_json_free(&d);
            }
        } else {
            len = seed.len;
            memcpy(buf, seed.data, len);
            len = mutate(buf, len, sizeof buf);
            run_fcgi(buf, len);
        }
    }
    st_buf_free(&seed);
    printf("fuzz_parsers: %ld rounds, no crashes\n", rounds);
    return 0;
}
