/* test_core.c - unit tests for src/core and the dispatcher, on the stub platform.

   Build and run: make test. Each CHECK names what it establishes; the run fails if
   any check does. Where a check guards a security property it says so. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_buf.h"
#include "st_fcgi.h"
#include "st_json.h"
#include "st_http.h"
#include "st_route.h"
#include "st_app.h"

static int checks, failures;

#define CHECK(cond, what) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what); } } while (0)

/* ------------------------------------------------------------------ fcgi */

static void test_fcgi(void)
{
    st_buf b, out;
    st_fcgi_rec r;
    st_fcgi_conn c;
    unsigned char begin[8] = { 0, ST_FCGI_RESPONDER, ST_FCGI_KEEP_CONN, 0, 0, 0, 0, 0 };
    long used;
    int ev;

    st_buf_init(&b, 0);
    st_buf_init(&out, 0);

    st_fcgi_write(&b, ST_FCGI_BEGIN_REQUEST, 1, begin, 8);
    used = st_fcgi_parse((unsigned char *) b.data, b.len - 1, &r);
    CHECK(used == 0, "a partial record asks for more input");
    used = st_fcgi_parse((unsigned char *) b.data, b.len, &r);
    CHECK(used == 16 && r.type == ST_FCGI_BEGIN_REQUEST && r.id == 1 && r.len == 8,
          "a whole BEGIN_REQUEST record parses");
    b.data[0] = 2;
    CHECK(st_fcgi_parse((unsigned char *) b.data, b.len, &r) == -1, "a wrong version byte is refused");

    {   /* long names and values take the four-byte length form */
        char big[300];
        st_buf p;
        memset(big, 'v', sizeof big - 1); big[sizeof big - 1] = '\0';
        st_buf_init(&p, 0);
        st_fcgi_put_pair(&p, "SHORT", "x");
        st_fcgi_put_pair(&p, "LONG", big);
        CHECK(p.len == 2 + 5 + 1 + 1 + 4 + 4 + 299, "pair lengths use 1- and 4-byte forms");
        st_buf_free(&p);
    }
    {   /* a pair whose length runs past the end is malformed */
        unsigned char bad[3] = { 5, 1, 'a' };
        CHECK(st_fcgi_pairs(bad, 3, NULL, NULL) == -1, "an overlong pair length is refused");
    }

    /* A whole request through the connection state machine. */
    st_fcgi_conn_init(&c, 4096, 4096);
    st_buf_reset(&b);
    st_fcgi_write(&b, ST_FCGI_BEGIN_REQUEST, 7, begin, 8);
    {
        st_buf p; st_buf_init(&p, 0);
        st_fcgi_put_pair(&p, "REQUEST_METHOD", "GET");
        st_fcgi_write(&b, ST_FCGI_PARAMS, 7, p.data, p.len);
        st_buf_free(&p);
    }
    st_fcgi_write(&b, ST_FCGI_PARAMS, 7, NULL, 0);
    st_fcgi_write(&b, ST_FCGI_STDIN, 7, "hi", 2);
    st_fcgi_write(&b, ST_FCGI_STDIN, 7, NULL, 0);
    ev = ST_FCGI_NONE;
    while (b.len && (used = st_fcgi_parse((unsigned char *) b.data, b.len, &r)) > 0) {
        ev = st_fcgi_conn_handle(&c, &r, &out);
        st_buf_consume(&b, (size_t) used);
    }
    CHECK(ev == ST_FCGI_READY && c.id == 7 && c.keep_conn, "a request becomes ready after both streams end");
    CHECK(c.body.len == 2 && !memcmp(c.body.data, "hi", 2), "stdin is collected");
    CHECK(out.len == 0, "nothing is written before the response");

    {   /* a second request id while one is active is refused, not mixed in */
        st_buf_reset(&b);
        st_fcgi_write(&b, ST_FCGI_BEGIN_REQUEST, 8, begin, 8);
        st_fcgi_parse((unsigned char *) b.data, b.len, &r);
        st_fcgi_conn_handle(&c, &r, &out);
        CHECK(out.len == 16 && (unsigned char) out.data[1] == ST_FCGI_END_REQUEST &&
              out.data[3] == 8 && out.data[12] == ST_FCGI_CANT_MPX_CONN,
              "a multiplexed request gets END_REQUEST/CANT_MPX_CONN");
    }

    st_buf_reset(&out);
    st_fcgi_respond(&out, 7, "Status: 200\r\n\r\n", 15);
    CHECK(out.len == 8 + 15 + 8 + 16, "a response is STDOUT, empty STDOUT, END_REQUEST");

    {   /* GET_VALUES on id 0 answers what we support */
        st_buf p; st_buf_init(&p, 0); st_buf_reset(&out); st_buf_reset(&b);
        st_fcgi_put_pair(&p, "FCGI_MPXS_CONNS", "");
        st_fcgi_write(&b, ST_FCGI_GET_VALUES, 0, p.data, p.len);
        st_fcgi_parse((unsigned char *) b.data, b.len, &r);
        st_fcgi_conn_handle(&c, &r, &out);
        CHECK(out.len > 8 && (unsigned char) out.data[1] == ST_FCGI_GET_VALUES_RESULT &&
              strstr(out.data + 8, "FCGI_MPXS_CONNS") != NULL, "GET_VALUES is answered");
        st_buf_free(&p);
    }
    st_fcgi_conn_free(&c);
    st_buf_free(&b);
    st_buf_free(&out);
}

/* ------------------------------------------------------------------ json */

static int parses(const char *s)
{
    st_jdoc d; char err[80];
    int ok = st_json_parse(&d, s, strlen(s), err, sizeof err) == 0;
    if (ok) st_json_free(&d);
    return ok;
}

static void test_json(void)
{
    st_jdoc d;
    char err[80], l1[32];
    st_buf b;
    st_jw w;
    long long n;
    char deep[80];
    int i;

    CHECK(st_json_parse(&d, "{\"a\":[1,2.5,-3e2],\"b\":\"x\\u00e9\\ud83d\\ude00\",\"c\":true,\"d\":null}",
                        strlen("{\"a\":[1,2.5,-3e2],\"b\":\"x\\u00e9\\ud83d\\ude00\",\"c\":true,\"d\":null}"),
                        err, sizeof err) == 0, "a mixed document parses");
    CHECK(st_json_get(d.root, "a")->count == 3, "array count");
    CHECK(!strcmp(st_json_get_str(d.root, "b"), "x\xc3\xa9\xf0\x9f\x98\x80"), "escapes and surrogate pairs decode to UTF-8");
    CHECK(st_json_get_int(d.root, "a", 0, 1, &n) == 0, "an array is not an int");
    st_json_free(&d);

    CHECK(!parses("{\"a\":1,\"a\":2}"), "duplicate keys are refused");
    CHECK(!parses("\"\\u0000\""), "NUL in a string is refused");
    CHECK(!parses("\"\\ud800\""), "a lone surrogate is refused");
    CHECK(!parses("\"\xc0\xaf\""), "overlong UTF-8 is refused");
    CHECK(!parses("[1,]"), "a trailing comma is refused");
    CHECK(!parses("01"), "a leading zero is refused");
    CHECK(!parses("{} x"), "trailing characters are refused");
    CHECK(!parses("\"abc"), "an unterminated string is refused");
    CHECK(parses("  {\"k\" : [ ] }  "), "whitespace is allowed around tokens");
    for (i = 0; i < 40; i++) { deep[i] = '['; deep[40 + i] = ']'; }
    CHECK(st_json_parse(&d, deep, 80, err, sizeof err) == -1, "nesting beyond the limit is refused");

    CHECK(st_json_parse(&d, "{\"n\":42,\"f\":4.5,\"big\":1e300}", 28, err, sizeof err) == 0, "numbers parse");
    CHECK(st_json_get_int(d.root, "n", 0, 100, &n) && n == 42, "a whole number reads as an int");
    CHECK(!st_json_get_int(d.root, "f", 0, 100, &n), "a fraction is not an int");
    CHECK(!st_json_get_int(d.root, "big", 0, 100, &n), "out of range is not an int");
    st_json_free(&d);

    CHECK(st_json_latin1("caf\xc3\xa9", 5, l1, sizeof l1) == 0 && !strcmp(l1, "caf\xe9"), "UTF-8 to Latin-1");
    CHECK(st_json_latin1("\xe2\x82\xac", 3, l1, sizeof l1) == -1, "a character above U+00FF is refused for Latin-1");

    st_buf_init(&b, 0);
    st_jw_init(&w, &b);
    st_jw_obj(&w);
    st_jw_kstr(&w, "owner", "M\xfcller <x>");
    st_jw_key(&w, "l"); st_jw_arr(&w); st_jw_int(&w, 1); st_jw_bool(&w, 0); st_jw_null(&w); st_jw_arr_end(&w);
    st_jw_obj_end(&w);
    CHECK(!strcmp(st_buf_cstr(&b), "{\"owner\":\"M\xc3\xbcller \\u003cx\\u003e\",\"l\":[1,false,null]}"),
          "the writer converts Latin-1 and escapes markup");
    CHECK(parses(b.data), "the writer's output parses");
    st_buf_free(&b);
}

/* ------------------------------------------------------- http and route */

typedef struct { const char *n, *v; } hdr;

static st_buf mkparams(const char *method, const char *uri, const hdr *h)
{
    st_buf p;
    st_buf_init(&p, 0);
    st_fcgi_put_pair(&p, "REQUEST_METHOD", method);
    st_fcgi_put_pair(&p, "REQUEST_URI", uri);
    for (; h && h->n; h++) st_fcgi_put_pair(&p, h->n, h->v);
    return p;
}

static void test_http(void)
{
    hdr h[] = { { "HTTP_COOKIE", "a=1; steward_session=abc ; z=9" }, { "REMOTE_ADDR", "10.0.0.1" }, { 0, 0 } };
    st_buf p = mkparams("GET", "/api/v1/users?filter=A%2BB&x=1+2&bad=%zz", h);
    st_request r;
    char v[64], args[ST_ROUTE_ARGS][ST_ARG_MAX], u[13];
    int n;

    CHECK(st_request_init(&r, (unsigned char *) p.data, p.len, NULL, 0) == 0, "a request builds from params");
    CHECK(!strcmp(r.path, "/api/v1/users") && !strcmp(r.query, "filter=A%2BB&x=1+2&bad=%zz"), "path and query split");
    CHECK(st_req_cookie(&r, "steward_session", v, sizeof v) && !strcmp(v, "abc"), "cookie found and trimmed");
    CHECK(!st_req_cookie(&r, "steward", v, sizeof v), "cookie names match exactly");
    CHECK(st_req_query(&r, "filter", v, sizeof v) && !strcmp(v, "A+B"), "query %2B decodes to +");
    CHECK(st_req_query(&r, "x", v, sizeof v) && !strcmp(v, "1 2"), "query + decodes to space");
    CHECK(!st_req_query(&r, "bad", v, sizeof v), "a malformed escape is refused");
    st_request_free(&r);
    st_buf_free(&p);

    CHECK(st_route_match("/api/v1/users/{u}", "/api/v1/users/SYSTEM", args, 4, &n) == 1 &&
          n == 1 && !strcmp(args[0], "SYSTEM"), "a capture matches one segment");
    CHECK(st_route_match("/api/v1/users/{u}", "/api/v1/users/a%2Fb", args, 4, &n) == -1,
          "an encoded slash in a segment is refused");
    CHECK(st_route_match("/api/v1/users/{u}", "/api/v1/users/a%00", args, 4, &n) == -1,
          "an encoded NUL is refused");
    CHECK(st_route_match("/api/v1/users/{u}", "/api/v1/users/", args, 4, &n) == 0, "an empty segment does not match");
    CHECK(st_route_match("/api/v1/session", "/api/v1/session/", args, 4, &n) == 0, "a trailing slash does not match");
    CHECK(st_route_match("/api/v1/session", "/api/v1/sessions", args, 4, &n) == 0, "a longer segment does not match");

    CHECK(st_valid_username("steward_test", u) && !strcmp(u, "STEWARD_TEST"), "usernames are upcased (PHASE0)");
    CHECK(st_valid_username("MAIL$SERVER", u), "$ is allowed in usernames");
    CHECK(!st_valid_username("a b", u) && !st_valid_username("", u) &&
          !st_valid_username("THIRTEENCHARS", u) && !st_valid_username("x\"y", u), "bad usernames are refused");
    CHECK(st_valid_ip("192.0.2.1") && st_valid_ip("2001:db8::1") && !st_valid_ip("a b") &&
          !st_valid_ip("host.example"), "client addresses are validated");
}

/* ----------------------------------------------------------- proxies (D7) */

static void origin_of(const hdr *h, const char *proxies, st_ctx *c, st_request *r, st_buf *p)
{
    *p = mkparams("POST", "/api/v1/session", h);
    st_request_init(r, (unsigned char *) p->data, p->len, NULL, 0);
    memset(c, 0, sizeof *c);
    c->req = r;
    st_app_origin(c, proxies);
}

static void test_proxy(void)
{
    st_ctx c; st_request r; st_buf p;
    hdr direct[] = { { "REMOTE_ADDR", "198.51.100.7" }, { "HTTP_HOST", "vms.example" },
                     { "HTTP_X_FORWARDED_FOR", "203.0.113.9" }, { "HTTP_X_FORWARDED_PROTO", "https" }, { 0, 0 } };
    hdr npm[] = { { "REMOTE_ADDR", "172.17.0.2" }, { "HTTP_HOST", "steward.example" },
                  { "HTTP_X_FORWARDED_FOR", "6.6.6.6, 203.0.113.9" }, { "HTTP_X_FORWARDED_PROTO", "https" },
                  { "HTTP_X_FORWARDED_PREFIX", "/steward/" }, { 0, 0 } };
    hdr chain[] = { { "REMOTE_ADDR", "127.0.0.1" }, { "HTTP_HOST", "h" },
                    { "HTTP_X_FORWARDED_FOR", "203.0.113.9, 172.17.0.2" }, { 0, 0 } };
    hdr junk[] = { { "REMOTE_ADDR", "127.0.0.1" }, { "HTTP_HOST", "h" },
                   { "HTTP_X_FORWARDED_FOR", "not an ip, 203.0.113.9" },
                   { "HTTP_X_FORWARDED_PREFIX", "/../etc" }, { "HTTP_X_FORWARDED_HOST", "evil\"host" }, { 0, 0 } };

    origin_of(direct, "", &c, &r, &p);
    CHECK(!strcmp(c.client, "198.51.100.7") && !strcmp(c.scheme, "http") && !strcmp(c.host, "vms.example"),
          "with no trusted proxies, forwarded headers are ignored (spoofing guard)");
    st_request_free(&r); st_buf_free(&p);

    origin_of(direct, "127.0.0.1", &c, &r, &p);
    CHECK(!strcmp(c.client, "198.51.100.7"), "forwarded headers from an untrusted peer are ignored");
    st_request_free(&r); st_buf_free(&p);

    origin_of(npm, "172.17.0.0/16", &c, &r, &p);
    CHECK(!strcmp(c.client, "203.0.113.9"), "behind a trusted proxy, the client is the rightmost untrusted hop");
    CHECK(!strcmp(c.scheme, "https") && !strcmp(c.host, "steward.example") && !strcmp(c.prefix, "/steward"),
          "scheme from X-Forwarded-Proto, prefix trimmed");
    st_request_free(&r); st_buf_free(&p);

    origin_of(chain, "127.0.0.1, 172.17.0.0/16", &c, &r, &p);
    CHECK(!strcmp(c.client, "203.0.113.9"), "a chain of trusted proxies is walked through");
    st_request_free(&r); st_buf_free(&p);

    origin_of(junk, "127.0.0.1", &c, &r, &p);
    CHECK(!strcmp(c.client, "203.0.113.9"), "the walk stops at a malformed hop and keeps the last good one");
    CHECK(c.prefix[0] == '\0' && !strcmp(c.host, "h"), "a bad prefix or forwarded host is ignored");
    st_request_free(&r); st_buf_free(&p);
}

/* ------------------------------------------- dispatcher, end to end on stub */

typedef struct { st_response resp; char cookie[100]; char csrf[65]; } result;

static void call(const char *method, const char *uri, const hdr *extra, const char *body, result *out)
{
    hdr h[16];
    int n = 0;
    st_buf p;
    st_request r;
    h[n].n = "REMOTE_ADDR"; h[n++].v = "127.0.0.1";
    h[n].n = "HTTP_HOST"; h[n++].v = "steward.test";
    if (body) { h[n].n = "CONTENT_TYPE"; h[n++].v = "application/json"; }
    for (; extra && extra->n && n < 15; extra++) h[n++] = *extra;
    h[n].n = NULL;
    p = mkparams(method, uri, h);
    st_request_init(&r, (unsigned char *) p.data, p.len, body, body ? strlen(body) : 0);
    st_resp_init(&out->resp);
    st_app_handle(&r, 0, &out->resp);
    st_request_free(&r);
    st_buf_free(&p);
    {   /* pick up a Set-Cookie token and a csrf value, as a browser script would */
        const char *sc = strstr(st_buf_cstr(&out->resp.headers), "steward_session=");
        const char *cs = strstr(st_buf_cstr(&out->resp.body), "\"csrf\":\"");
        if (sc) { sscanf(sc, "steward_session=%99[^;]", out->cookie); }
        if (cs) { memcpy(out->csrf, cs + 8, 64); out->csrf[64] = '\0'; }
    }
}

static void test_dispatch(void)
{
    result a, b;
    char cookie[140];
    hdr with_cookie[3], with_csrf[4], cross[3];

    memset(&a, 0, sizeof a);
    call("GET", "/api/v1/nope", NULL, NULL, &a);
    CHECK(a.resp.status == 404, "unknown endpoint is 404");
    st_resp_free(&a.resp);

    call("PUT", "/api/v1/session", NULL, NULL, &a);
    CHECK(a.resp.status == 405 && strstr(st_buf_cstr(&a.resp.headers), "Allow: POST, GET, DELETE"),
          "wrong method is 405 with Allow");
    st_resp_free(&a.resp);

    call("GET", "/api/v1/session", NULL, NULL, &a);
    CHECK(a.resp.status == 401, "whoami without a session is 401");
    st_resp_free(&a.resp);

    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_test\",\"password\":\"wrong\"}", &a);
    CHECK(a.resp.status == 401 && !strstr(a.resp.body.data, "password"), "a wrong password is a plain 401");
    st_resp_free(&a.resp);

    call("POST", "/api/v1/session", NULL, "{\"username\":\"DISABLED\",\"password\":\"disabled-pass\"}", &b);
    CHECK(b.resp.status == 401 && !strstr(b.resp.body.data, "disabled"),
          "a disabled account looks the same as a wrong password (no username probing)");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/session", NULL, "{\"username\":\"EXPIRED\",\"password\":\"expired-pass\"}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "password-expired"),
          "an expired password does not get a session (PHASE0 #5)");
    CHECK(!strstr(st_buf_cstr(&b.resp.headers), "Set-Cookie"), "and no cookie");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/session", NULL, "{\"username\":\"STEWARD_TEST\"}", &b);
    CHECK(b.resp.status == 400, "a missing password is 400");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/session", NULL, "{bad", &b);
    CHECK(b.resp.status == 400, "bad JSON is 400");
    st_resp_free(&b.resp);

    cross[0].n = "HTTP_ORIGIN"; cross[0].v = "https://evil.example"; cross[1].n = NULL;
    call("POST", "/api/v1/session", cross, "{\"username\":\"STEWARD_TEST\",\"password\":\"test-pass\"}", &b);
    CHECK(b.resp.status == 403, "a cross-origin login is refused");
    st_resp_free(&b.resp);

    memset(&a, 0, sizeof a);
    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_test\",\"password\":\"test-pass\"}", &a);
    CHECK(a.resp.status == 201 && strlen(a.cookie) == 64 && strlen(a.csrf) == 64, "a good login gets a session");
    CHECK(strstr(st_buf_cstr(&a.resp.headers), "HttpOnly; SameSite=Strict; Secure") != NULL,
          "the cookie is HttpOnly, SameSite=Strict and Secure");
    st_resp_free(&a.resp);

    sprintf(cookie, "steward_session=%s", a.cookie);
    with_cookie[0].n = "HTTP_COOKIE"; with_cookie[0].v = cookie; with_cookie[1].n = NULL;
    call("GET", "/api/v1/session", with_cookie, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"username\":\"STEWARD_TEST\"") &&
          strstr(b.resp.body.data, "\"current_privileges\":[\"TMPMBX\",\"NETMBX\"]"),
          "whoami reports the persona's own privileges");
    st_resp_free(&b.resp);

    call("DELETE", "/api/v1/session", with_cookie, NULL, &b);
    CHECK(b.resp.status == 403, "logout without the CSRF header is refused");
    st_resp_free(&b.resp);

    with_csrf[0] = with_cookie[0];
    with_csrf[1].n = "HTTP_X_STEWARD_CSRF";
    with_csrf[1].v = "0000000000000000000000000000000000000000000000000000000000000000";
    with_csrf[2].n = NULL;
    call("DELETE", "/api/v1/session", with_csrf, NULL, &b);
    CHECK(b.resp.status == 403, "logout with a wrong CSRF token is refused");
    st_resp_free(&b.resp);

    with_csrf[1].v = a.csrf;
    call("DELETE", "/api/v1/session", with_csrf, NULL, &b);
    CHECK(b.resp.status == 204 && strstr(st_buf_cstr(&b.resp.headers), "Max-Age=0"), "logout ends the session");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/session", with_cookie, NULL, &b);
    CHECK(b.resp.status == 401, "the old cookie no longer works");
    st_resp_free(&b.resp);

    CHECK(!st_plat_persona_active(), "no persona is left active after any request");
}

int main(void)
{
    st_app_config cfg;
    st_plat_config pc;
    st_err e;
    memset(&pc, 0, sizeof pc);
    pc.audit_file = "/dev/null";
    st_plat_init(&pc, &e);
    cfg.idle_secs = 900;
    cfg.absolute_secs = 28800;
    cfg.cookie_secure = 1;
    cfg.trusted_proxies = "";
    st_app_init(&cfg);

    test_fcgi();
    test_json();
    test_http();
    test_proxy();
    test_dispatch();
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
