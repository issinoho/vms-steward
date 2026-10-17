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
#include "st_lnm.h"
#include "st_proc.h"
#include "st_queue.h"
#include "st_sysgen.h"
#include "st_license.h"
#include "st_product.h"
#include "st_mrec.h"
#include "st_errlog.h"
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

static void test_privileges(void)
{
    result a, b;
    char cookie[140];
    hdr h[4];

    memset(&a, 0, sizeof a);
    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", &a);
    CHECK(a.resp.status == 201, "admin signs in");
    st_resp_free(&a.resp);
    snprintf(cookie, sizeof cookie, "steward_session=%s", a.cookie);
    h[0].n = "HTTP_COOKIE"; h[0].v = cookie;
    h[1].n = "HTTP_X_STEWARD_CSRF"; h[1].v = a.csrf;
    h[2].n = NULL;

    call("GET", "/api/v1/session", h, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"current_privileges\":[\"TMPMBX\",\"OPER\",\"NETMBX\"]"),
          "a session starts with the default privileges only (D9)");
    CHECK(strstr(b.resp.body.data, "\"enabled_privileges\":[]") != NULL, "nothing switched on yet");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/session/privileges", h, "{\"enabled\":[\"sysprv\"]}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"current_privileges\":[\"TMPMBX\",\"OPER\",\"NETMBX\",\"SYSPRV\"]"),
          "an authorized privilege can be switched on, and takes effect at once");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/session", h, NULL, &b);
    CHECK(strstr(b.resp.body.data, "\"enabled_privileges\":[\"SYSPRV\"]") &&
          strstr(b.resp.body.data, "\"SYSPRV\"]"), "and stays on for the session's later requests");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/session/privileges", h, "{\"enabled\":[\"SYSPRV\",\"SECURITY\"]}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "not authorized for: SECURITY"),
          "a privilege the user is not authorized for is refused, by name");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/session/privileges", h, "{\"enabled\":[\"NOTAPRIV\"]}", &b);
    CHECK(b.resp.status == 422, "an unknown privilege name is refused");
    st_resp_free(&b.resp);

    h[1].n = NULL;
    call("PUT", "/api/v1/session/privileges", h, "{\"enabled\":[]}", &b);
    CHECK(b.resp.status == 403, "changing privileges needs the CSRF token");
    st_resp_free(&b.resp);
    h[1].n = "HTTP_X_STEWARD_CSRF";

    call("PUT", "/api/v1/session/privileges", h, "{\"enabled\":[]}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"current_privileges\":[\"TMPMBX\",\"OPER\",\"NETMBX\"]"),
          "an empty list goes back to the defaults");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- names, filters, wildcards */

static void test_filters(void)
{
    char out[32];
    CHECK(st_valid_ident("apache$www", out) && !strcmp(out, "APACHE$WWW"), "identifier names are upcased");
    CHECK(!st_valid_ident("12345", out), "an all-digit identifier name is refused");
    CHECK(!st_valid_ident("", out) && !st_valid_ident("A234567890123456789012345678901X", out),
          "identifier names are 1-31 characters");
    CHECK(!st_valid_ident("BAD-NAME", out) && !st_valid_ident("A B", out), "and only A-Z 0-9 _ $");
    CHECK(st_valid_filter("steward*", out) && !strcmp(out, "STEWARD*"), "a filter is upcased");
    CHECK(!st_valid_filter("a\"b", out) && !st_valid_filter("a\\b", out) && !st_valid_filter("a\nb", out),
          "a filter refuses quotes, backslashes and control characters");
    CHECK(st_wild_match("STEW*", "STEWARD_TEST") && st_wild_match("*TEST", "STEWARD_TEST") &&
          st_wild_match("S%EWARD*", "steward_adm") && st_wild_match("*", ""),
          "DCL wildcards: * any run, % one character, case-insensitive");
    CHECK(!st_wild_match("STEW%", "STEWARD") && !st_wild_match("*X*", "STEWARD") && !st_wild_match("", "A"),
          "and a non-match is a non-match");
    CHECK(st_wild_match("*A*B*C*D*", "AXBXCXD") && !st_wild_match("*A*B*C*D*E", "AXBXCXDX"),
          "several stars backtrack correctly");
    CHECK(st_filter_match("TEST", "STEWARD_TEST", NULL) && st_filter_match("probe", "X", "steward probe"),
          "without wildcards a filter is a substring of the name or of the owner");
    CHECK(!st_filter_match("STEW*", "X", "STEWARD") && st_filter_match("", "X", NULL),
          "with wildcards it matches the name only; empty matches everything");
}

/* ------------------------------------------------- users and identifiers (Phase 2) */

static void sign_in(const char *body, char *cookie, size_t clen, char csrf[65])
{
    result a;
    memset(&a, 0, sizeof a);
    call("POST", "/api/v1/session", NULL, body, &a);
    st_resp_free(&a.resp);
    snprintf(cookie, clen, "steward_session=%s", a.cookie);
    memcpy(csrf, a.csrf, 65);
}

static void test_users(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    hdr t[2], adm[3];

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = NULL;
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac;
    adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;

    call("GET", "/api/v1/users", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "listing users needs a session");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "RMS-E-PRV"),
          "an unprivileged user cannot list users: the OS refuses, and says why");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users/steward_test", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"uic\":\"[362,1]\"") &&
          strstr(b.resp.body.data, "\"quotas\":{\"prio\":4"),
          "but can read their own record (reduced data, as $GETUAI allows)");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users/SYSTEM", t, NULL, &b);
    CHECK(b.resp.status == 403, "and not someone else's");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users", adm, NULL, &b);
    CHECK(b.resp.status == 403, "an admin with SYSPRV authorized but not switched on is refused too (D9)");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"SYSPRV\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"users\":[{\"username\":\"DEFAULT\"") &&
          strstr(b.resp.body.data, "\"next\":null"),
          "with SYSPRV on, users list in SYSUAF (alphabetical) order");
    CHECK(strstr(b.resp.body.data, "\"flags\":[\"DISUSER\"]") != NULL, "flags are named as AUTHORIZE names them");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users?limit=2", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"next\":\"DISABLED\""), "a page ends with a cursor");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users?limit=2&after=EXPIRED", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "[{\"username\":\"STEWARD_ADM\"") &&
          strstr(b.resp.body.data, "\"next\":\"STEWARD_TEST\""), "and the cursor gives the next page");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users?filter=steward*", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "STEWARD_ADM") &&
          strstr(b.resp.body.data, "STEWARD_TEST") && !strstr(b.resp.body.data, "SYSTEM"),
          "a wildcard filter matches usernames");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users?filter=manager", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"username\":\"SYSTEM\"") &&
          !strstr(b.resp.body.data, "STEWARD"), "a plain filter also matches owners");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users?limit=0", adm, NULL, &b);
    CHECK(b.resp.status == 400, "limit is validated");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users?filter=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", adm, NULL, &b);
    CHECK(b.resp.status == 400, "an over-long filter is refused, not ignored (it would list everyone)");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users?filter=%zz", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a badly encoded filter is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users?after=bad-name", adm, NULL, &b);
    CHECK(b.resp.status == 400, "the cursor is validated");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/NOBODY", adm, NULL, &b);
    CHECK(b.resp.status == 404, "a user that does not exist is 404");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/a%2Fb", adm, NULL, &b);
    CHECK(b.resp.status == 400 || b.resp.status == 404, "a malformed username never reaches the OS");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users/STEWARD_ADM/identifiers", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"name\":\"STEWARD_DEMO\",\"value\":\"%X80010001\""),
          "identifiers held, with values as AUTHORIZE shows them");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/identifiers", t, NULL, &b);
    CHECK(b.resp.status == 200, "anyone may read the rights database, as on OpenVMS (PHASE2.md)");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_ADM/identifiers", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "STEWARD_DEMO"),
          "including another user's identifiers, though not their UAF record");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/BATCH/identifiers", t, NULL, &b);
    CHECK(b.resp.status == 404, "a general identifier is not a user");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/identifiers", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "[{\"name\":\"BATCH\"") &&
          !strstr(b.resp.body.data, "\"type\":\"uic\""),
          "identifiers list general ones by default, sorted by name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers?type=uic&filter=steward*", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"value\":\"[362,2]\",\"type\":\"uic\""),
          "UIC identifiers on request, with octal UICs");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers?type=bogus", adm, NULL, &b);
    CHECK(b.resp.status == 400, "type is validated");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/identifiers/steward_demo", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"attributes\":[\"RESOURCE\"]"),
          "identifier detail names its attributes");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers/STEWARD_OPS/holders", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"username\":\"STEWARD_ADM\",\"uic\":\"[362,2]\"") &&
          strstr(b.resp.body.data, "STEWARD_TEST"), "holders are listed with their UICs");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers/NO_SUCH_ID", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOSUCHID"), "an unknown identifier is 404");
    st_resp_free(&b.resp);

    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- changes (Phase 3) */

/* The ETag from a GET response's headers. */
static void etag_of(const result *r, char *out, size_t n)
{
    const char *h = strstr(st_buf_cstr((st_buf *) &r->resp.headers), "ETag: ");
    out[0] = '\0';
    if (h) { h += 6; snprintf(out, n, "%.*s", (int) strcspn(h, "\r\n"), h); }
}

static void test_edit(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65], etag[48], etag2[48];
    hdr t[4], adm[4];   /* one slot more than the most headers used: call() stops at n == NULL */

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL; t[3].n = NULL;
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf;
    adm[2].n = NULL; adm[3].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"SYSPRV\"]}", &b);
    st_resp_free(&b.resp);

    /* ---- PATCH a user, with optimistic concurrency */
    call("GET", "/api/v1/users/STEWARD_TEST", adm, NULL, &b);
    etag_of(&b, etag, sizeof etag);
    CHECK(b.resp.status == 200 && strlen(etag) == 34 && strstr(b.resp.body.data, "\"etag\":"),
          "a user GET carries an ETag, in the header and the body");
    st_resp_free(&b.resp);

    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"x\"}", &b);
    CHECK(b.resp.status == 428, "a PATCH without If-Match is refused (428)");
    st_resp_free(&b.resp);
    adm[2].n = "HTTP_IF_MATCH"; adm[2].v = "\"00000000000000000000000000000000\"";
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"x\"}", &b);
    CHECK(b.resp.status == 412 && strstr(st_buf_cstr(&b.resp.headers), etag),
          "a stale If-Match is refused (412), with the current ETag");
    st_resp_free(&b.resp);

    adm[2].v = etag;
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"x\",\"shoe_size\":9}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "shoe_size"), "an unknown field is refused, by name");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"0123456789012345678901234567890123\"}", &b);
    CHECK(b.resp.status == 422, "an owner longer than 31 characters is refused, not trimmed");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"a\\u0007b\"}", &b);
    CHECK(b.resp.status == 422, "control characters are refused");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"quotas\":{\"prio\":99}}", &b);
    CHECK(b.resp.status == 422, "a quota out of range is refused (PRIO is 0-31)");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"flags\":[\"NOSUCHFLAG\"]}", &b);
    CHECK(b.resp.status == 422, "an unknown flag is refused");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"default_directory\":\"[A B]\"}", &b);
    CHECK(b.resp.status == 422, "a directory with a space is refused");
    st_resp_free(&b.resp);

    call("PATCH", "/api/v1/users/STEWARD_TEST", adm,
         "{\"owner\":\"Changed owner\",\"flags\":[\"DISWELCOME\"],\"quotas\":{\"prio\":5},"
         "\"secondary_days\":[\"SAT\"],\"restricted_hours\":{\"batch\":{\"primary\":[0,1,2]}},"
         "\"authorized_privileges\":[\"TMPMBX\",\"NETMBX\",\"OPER\"],\"password\":{\"lifetime_days\":30}}", &b);
    etag_of(&b, etag2, sizeof etag2);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"owner\":\"Changed owner\"") &&
          strstr(b.resp.body.data, "\"flags\":[\"DISWELCOME\"]") && strstr(b.resp.body.data, "\"prio\":5") &&
          strstr(b.resp.body.data, "\"secondary_days\":[\"SAT\"]") &&
          strstr(b.resp.body.data, "\"batch\":{\"primary\":[0,1,2]") &&
          strstr(b.resp.body.data, "\"lifetime_days\":30") &&
          strstr(b.resp.body.data, "\"authorized_privileges\":[\"TMPMBX\",\"OPER\",\"NETMBX\"]"),
          "a PATCH changes what it names, and returns the record as it now is");
    CHECK(strcmp(etag, etag2) != 0, "and the ETag changes with it");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"owner\":\"again\"}", &b);
    CHECK(b.resp.status == 412, "the old ETag no longer works after a change");
    st_resp_free(&b.resp);
    adm[2].v = etag2;
    call("PATCH", "/api/v1/users/STEWARD_TEST", adm,
         "{\"owner\":\"Test account\",\"flags\":[],\"quotas\":{\"prio\":4},"
         "\"secondary_days\":[\"SAT\",\"SUN\"],\"restricted_hours\":{\"batch\":{\"primary\":[]}},"
         "\"authorized_privileges\":[\"TMPMBX\",\"NETMBX\"],\"password\":{\"lifetime_days\":90}}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"owner\":\"Test account\""), "and it can be put back");
    st_resp_free(&b.resp);
    adm[2].n = NULL;

    t[2].n = "HTTP_IF_MATCH"; t[2].v = etag;
    call("GET", "/api/v1/users/STEWARD_TEST", t, NULL, &b);
    etag_of(&b, etag, sizeof etag);
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/users/STEWARD_TEST", t, "{\"owner\":\"mine now\"}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"),
          "a user without privilege cannot change even their own record: OpenVMS refuses");
    st_resp_free(&b.resp);
    t[2].n = NULL;

    /* ---- passwords */
    call("POST", "/api/v1/users/STEWARD_TEST/password", adm, "{\"password\":\"short\"}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "INVPWDLEN"),
          "setting a password below the account's minimum is refused by the system");
    st_resp_free(&b.resp);
    {   /* one over the system's longest (UAI$C_MAX_PWD_LENGTH: 32 on IA64), refused by Steward */
        char body[128], lim[24];
        int n = st_plat_password_max() + 1;
        snprintf(body, sizeof body, "{\"password\":\"%.*s\"}", n, "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
        snprintf(lim, sizeof lim, "1 to %d characters", n - 1);
        call("POST", "/api/v1/users/STEWARD_TEST/password", adm, body, &b);
        CHECK(b.resp.status == 422 && strstr(b.resp.body.data, lim),
              "a password longer than the system takes is refused before it reaches the system");
        st_resp_free(&b.resp);
    }
    call("POST", "/api/v1/users/STEWARD_TEST/password", adm, "{\"password\":\"a-long-enough-pass\",\"extra\":1}", &b);
    CHECK(b.resp.status == 422, "and unknown members are refused");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_TEST/password", adm, "{\"password\":\"a-long-enough-pass\",\"pre_expired\":true}", &b);
    CHECK(b.resp.status == 204, "an administrator sets a password, pre-expired");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_test\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "password-expired"),
          "the user cannot sign in with it until they change it");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/session/password", NULL,
         "{\"username\":\"steward_test\",\"current\":\"wrong-one\",\"new\":\"another-long-password\"}", &b);
    CHECK(b.resp.status == 401 && strstr(b.resp.body.data, "sign-in-failed"),
          "changing with a wrong current password looks exactly like a failed sign-in");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/session/password", NULL,
         "{\"username\":\"steward_test\",\"current\":\"a-long-enough-pass\",\"new\":\"short\"}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "password-refused") && strstr(b.resp.body.data, "INVPWDLEN"),
          "with the right current password, a refused new one says why");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/session/password", NULL,
         "{\"username\":\"steward_test\",\"current\":\"a-long-enough-pass\",\"new\":\"another-long-password\"}", &b);
    CHECK(b.resp.status == 204, "an expired password can be changed without signing in");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_test\",\"password\":\"another-long-password\"}", &b);
    CHECK(b.resp.status == 201, "and the new one signs in");
    st_resp_free(&b.resp);
    {   /* put the fixture back: minimum 0, the old password, minimum 15 */
        char et[48];
        call("GET", "/api/v1/users/STEWARD_TEST", adm, NULL, &b);
        etag_of(&b, et, sizeof et);
        st_resp_free(&b.resp);
        adm[2].n = "HTTP_IF_MATCH"; adm[2].v = et;
        call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"password\":{\"minimum_length\":0}}", &b);
        etag_of(&b, et, sizeof et);
        st_resp_free(&b.resp);
        call("POST", "/api/v1/users/STEWARD_TEST/password", adm, "{\"password\":\"test-pass\"}", &b);
        CHECK(b.resp.status == 204, "fixture restored: password");
        st_resp_free(&b.resp);
        call("PATCH", "/api/v1/users/STEWARD_TEST", adm, "{\"password\":{\"minimum_length\":15}}", &b);
        CHECK(b.resp.status == 200, "fixture restored: minimum length");
        st_resp_free(&b.resp);
        adm[2].n = NULL;
    }

    /* ---- grant, change, revoke */
    call("POST", "/api/v1/users/STEWARD_TEST/identifiers", adm, "{\"name\":\"steward_ops\",\"attributes\":[\"RESOURCE\"]}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "only attributes its identifier has"),
          "a holding attribute the identifier lacks is refused (OpenVMS would drop it silently)");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_TEST/identifiers", adm, "{\"name\":\"steward_demo\",\"attributes\":[\"RESOURCE\"]}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "{\"name\":\"STEWARD_DEMO\",\"value\":\"%X80010001\",\"attributes\":[\"RESOURCE\"]}"),
          "grant, with an attribute the identifier has");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_TEST/identifiers", adm, "{\"name\":\"STEWARD_DEMO\"}", &b);
    CHECK(b.resp.status == 409 && strstr(b.resp.body.data, "DUPIDENT"), "granting it twice is a conflict");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/users/STEWARD_TEST/identifiers/STEWARD_DEMO", adm, "{\"attributes\":[]}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"name\":\"STEWARD_DEMO\",\"value\":\"%X80010001\",\"attributes\":[]}"),
          "a holding's attributes can be changed");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_TEST/identifiers", adm, "{\"name\":\"STEWARD_ADM\"}", &b);
    CHECK(b.resp.status == 422, "a UIC identifier cannot be granted");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/users/STEWARD_TEST/identifiers/STEWARD_DEMO", adm, NULL, &b);
    CHECK(b.resp.status == 204, "revoke");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/users/STEWARD_TEST/identifiers/STEWARD_DEMO", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOSUCHID"), "revoking what is not held is 404");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_ADM/identifiers", t, "{\"name\":\"STEWARD_DEMO\"}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "RMS-E-PRV"), "an unprivileged user cannot grant: OpenVMS refuses");
    st_resp_free(&b.resp);

    /* ---- identifiers */
    call("POST", "/api/v1/identifiers", adm, "{\"name\":\"steward_test_id\",\"attributes\":[\"RESOURCE\"]}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"name\":\"STEWARD_TEST_ID\",\"value\":\"%X80010010\"") &&
          strstr(b.resp.body.data, "\"attributes\":[\"RESOURCE\"]"), "create an identifier; OpenVMS chooses the value");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/identifiers", adm, "{\"name\":\"STEWARD_TEST_ID\"}", &b);
    CHECK(b.resp.status == 409, "a duplicate name is a conflict");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/identifiers", adm, "{\"name\":\"OTHER_ID\",\"value\":\"%X00010001\"}", &b);
    CHECK(b.resp.status == 422, "a value without the general bit is refused");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/identifiers", t, "{\"name\":\"OTHER_ID\"}", &b);
    CHECK(b.resp.status == 403, "an unprivileged user cannot create one");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users/STEWARD_TEST/identifiers", adm, "{\"name\":\"STEWARD_TEST_ID\"}", &b);
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/identifiers/STEWARD_TEST_ID", adm, "{\"name\":\"STEWARD_TEST_ID2\",\"attributes\":[\"NOACCESS\"]}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"name\":\"STEWARD_TEST_ID2\"") &&
          strstr(b.resp.body.data, "\"attributes\":[\"NOACCESS\"]"), "rename, and replace the attributes");
    st_resp_free(&b.resp);
    call("PATCH", "/api/v1/identifiers/STEWARD_TEST", adm, "{\"name\":\"X\"}", &b);
    CHECK(b.resp.status == 422, "a UIC identifier cannot be renamed here");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/identifiers/STEWARD_TEST_ID2", adm, NULL, &b);
    CHECK(b.resp.status == 204, "delete an identifier that is still held");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_TEST/identifiers", adm, NULL, &b);
    CHECK(b.resp.status == 200 && !strstr(b.resp.body.data, "STEWARD_TEST_ID"),
          "and its holdings went with it, as on OpenVMS");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/identifiers/BATCH", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "changes need a session");
    st_resp_free(&b.resp);
    adm[1].n = NULL;
    call("DELETE", "/api/v1/identifiers/BATCH", adm, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "csrf"), "and the CSRF token");
    st_resp_free(&b.resp);

    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- the dashboard */

static void test_system(void)
{
    result b;
    char tc[140], tcsrf[65], hexkey[65];
    unsigned char token[32], key[32];
    st_session sess;
    st_err e;
    hdr t[3];

    call("GET", "/api/v1/system", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "the system overview needs a session");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = NULL; t[2].n = NULL;
    call("GET", "/api/v1/system", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"node\":\"X86VMS\"") &&
          strstr(b.resp.body.data, "\"os\":{\"name\":\"OpenVMS\",\"version\":\"E9.2-4\"") &&
          strstr(b.resp.body.data, "\"disks\":[{\"device\":\"DKA0:\"") &&
          strstr(b.resp.body.data, "\"system_disk\":true"),
          "the system overview: node, version, disks with the system disk first");
    CHECK(strstr(b.resp.body.data, "\"hidden\":17") != NULL,
          "processes the persona cannot see (no WORLD) are counted as hidden, not shown");
    CHECK(strstr(b.resp.body.data, "\"idle_ticks\":") && strstr(b.resp.body.data, "\"sampled_at_ms\":"),
          "CPU usage is left to the browser: idle ticks and when they were read");
    st_resp_free(&b.resp);

    /* A background poll is not activity (the idle timeout must still fire). */
    st_unhex(tc + strlen("steward_session="), token, 32);
    st_plat_sha256(token, 32, key);
    st_plat_session_get(key, &sess, &e);
    sess.last_seen = st_plat_time() - 850;
    st_plat_session_put(&sess, &e);
    t[1].n = "HTTP_X_STEWARD_BACKGROUND"; t[1].v = "1";
    call("GET", "/api/v1/system", t, NULL, &b);
    CHECK(b.resp.status == 200, "a background poll is served");
    st_resp_free(&b.resp);
    st_plat_session_get(key, &sess, &e);
    CHECK(st_plat_time() - sess.last_seen >= 850, "and does not count as activity: the idle clock is unchanged");
    t[1].n = NULL;
    call("GET", "/api/v1/system", t, NULL, &b);
    st_resp_free(&b.resp);
    st_plat_session_get(key, &sess, &e);
    CHECK(st_plat_time() - sess.last_seen < 5, "an ordinary request does count");
    (void) hexkey;
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- logical names (Phase 7) */

typedef struct { int n; st_lnm last; st_lnm_table table; int tables; char seen[64]; } lnm_seen;

static int lnm_collect(const st_lnm_table *t, const st_lnm *n, void *ctx)
{
    lnm_seen *s = ctx;
    if (strcmp(s->seen, t->name)) { s->tables++; st_copy(s->seen, sizeof s->seen, t->name); }
    s->table = *t;
    s->last = *n;
    s->n++;
    return 0;
}

static void lnm_feed(st_lnm_parser *p, const char *text)
{
    while (*text) {
        const char *nl = strchr(text, '\n');
        size_t n = nl ? (size_t) (nl - text) : strlen(text);
        st_lnm_parse_line(p, text, n);
        text += n + (nl ? 1 : 0);
    }
    st_lnm_parse_end(p);
}

static void test_lnm_parser(void)
{
    st_lnm_parser p;
    lnm_seen s;
    char out[64];

    /* As SHOW LOGICAL/FULL printed it on the x86 node (2026-10-11), with CRs. */
    memset(&s, 0, sizeof s);
    st_lnm_parse_init(&p, lnm_collect, &s);
    lnm_feed(&p, "\r\n\r\n(LNM$SYSTEM_TABLE)\t[kernel]  [shareable,system]\r\n"
                 "\t\t\t[Protection=(RWC,RWC,R,R)]  [Owner=[SYSTEM]]\r\n\r\n"
                 "  \"SYS$DISK\" [exec] = \"X86VMS$DKA0:\" [concealed,terminal]\r\n"
                 "  \"SYS$SYSROOT\" [exec] = \"X86VMS$DKA0:[SYS0.]\" [concealed,terminal]\r\n"
                 "\t= \"SYS$COMMON:\"\r\n");
    CHECK(s.n == 2 && !strcmp(s.last.name, "SYS$SYSROOT") && !strcmp(s.last.mode, "exec") && s.last.neq == 2 &&
          !strcmp(s.last.eq[0].value, "X86VMS$DKA0:[SYS0.]") && !strcmp(s.last.eq[0].attributes, "concealed,terminal") &&
          !strcmp(s.last.eq[1].value, "SYS$COMMON:") && !s.last.eq[1].attributes[0],
          "SHOW LOGICAL/FULL: a search list, with each equivalence's attributes");
    CHECK(!strcmp(s.table.name, "LNM$SYSTEM_TABLE") && !strcmp(s.table.mode, "kernel") &&
          !strcmp(s.table.attributes, "shareable,system") && !strcmp(s.table.protection, "(RWC,RWC,R,R)") &&
          !strcmp(s.table.owner, "[SYSTEM]"), "the table header: mode, attributes, protection, owner");

    memset(&s, 0, sizeof s);
    st_lnm_parse_init(&p, lnm_collect, &s);
    lnm_feed(&p, "(LNM$SYSTEM_DIRECTORY)\t[kernel]  [shareable,directory]\n"
                 "  \"LNM$CLUSTER_TABLE\" [kernel,no_alias,table,clusterwide] = \"\" [terminal]\n"
                 "  \"MOTD\" [exec] = \"Say \"\"hello\"\"\"\n"
                 "(LNM$GROUP_000362)\t[kernel]  [shareable,group]\n"
                 "\t\t\t[Protection=(RWCD,R,R,)]  [Owner=[362,*]]\n"
                 "  \"PROJECT\" [super] = \"DKA100:[P]\"\n");
    CHECK(s.n == 3 && s.tables == 2 && !strcmp(s.table.owner, "[362,*]") && !strcmp(s.last.name, "PROJECT"),
          "a search list of tables: each name with its own table");

    memset(&s, 0, sizeof s);
    st_lnm_parse_init(&p, lnm_collect, &s);
    lnm_feed(&p, "  \"MOTD\" [exec] = \"Say \"\"hello\"\"\"\n");
    CHECK(s.n == 1 && !strcmp(s.last.eq[0].value, "Say \"hello\""), "a doubled quote inside a value is one quote");
    memset(&s, 0, sizeof s);
    st_lnm_parse_init(&p, lnm_collect, &s);
    lnm_feed(&p, "  \"TAB\" [kernel,no_alias,table,clusterwide] = \"\" [terminal]\n");
    CHECK(s.n == 1 && !strcmp(s.last.mode, "kernel") && !strcmp(s.last.attributes, "no_alias,table,clusterwide") &&
          s.last.neq == 1 && !s.last.eq[0].value[0], "mode first, then the name's attributes; an empty equivalence");
    memset(&s, 0, sizeof s);
    st_lnm_parse_init(&p, lnm_collect, &s);
    lnm_feed(&p, "  \"BROKEN\" [exec] = \"no closing quote\n  \"%SYSTEM-F-NOPRIV\n%SYSTEM-F-NOLOGTAB, no logical name table matches\n");
    CHECK(s.n <= 2 && !strncmp(p.message, "%SYSTEM-F-NOLOGTAB", 18), "malformed lines are not trusted; a message is kept");
    {   /* more equivalences than are kept are counted, never overrun */
        char big[4096];
        int i;
        st_copy(big, sizeof big, "  \"MANY\" [exec] = \"0\"\n");
        for (i = 1; i < 40; i++) st_append(big, sizeof big, "\t= \"x\"\n");
        memset(&s, 0, sizeof s);
        st_lnm_parse_init(&p, lnm_collect, &s);
        lnm_feed(&p, big);
        CHECK(s.n == 1 && s.last.neq == ST_LNM_MAXEQ && s.last.more == 40 - ST_LNM_MAXEQ, "a long search list is capped and counted");
    }

    CHECK(st_valid_lnm_table("lnm$system_table", out) && !strcmp(out, "LNM$SYSTEM_TABLE"), "a table name, upper-cased");
    CHECK(!st_valid_lnm_table("LNM$PROCESS", out) && !st_valid_lnm_table("lnm$process_table", out) &&
          !st_valid_lnm_table("LNM$PROCESS_DIRECTORY", out) && !st_valid_lnm_table("LNM$JOB", out) &&
          !st_valid_lnm_table("LNM$FILE_DEV", out) && !st_valid_lnm_table("LNM$DIRECTORIES", out),
          "the process's own tables, and the names that search them, are refused (the service's settings)");
    CHECK(!st_valid_lnm_table("LNM$JOB_8217EDC0", out) && !st_valid_lnm_table("lnm$job_8217edc0", out) &&
          !st_valid_lnm_table("LNM$JOB_", out) && st_valid_lnm_table("LNM$JOBS", out),
          "a job table by its own name is refused, whatever its case (one of them is the service's)");
    CHECK(!st_valid_lnm_table("LNM$SYSTEM_TABLE/OUTPUT=X", out) && !st_valid_lnm_table("A B", out) &&
          !st_valid_lnm_table("", out) && !st_valid_lnm_table("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", out),
          "a table name with anything DCL could read as a qualifier, or too long, is refused");
    CHECK(st_valid_lnm_pattern("sys$*", out) && !strcmp(out, "SYS$*") && !st_valid_lnm_pattern("A'B", out) &&
          !st_valid_lnm_pattern("A B", out) && !st_valid_lnm_pattern("*/OUT", out), "a pattern: names and wildcards only");
    CHECK(st_valid_lnm_name("sys$sysroot") && st_valid_lnm_name("a b") && !st_valid_lnm_name("") &&
          !st_valid_lnm_name("x\ty"), "a name to translate: printable ASCII, case kept");
}

/* PUT api/v1/logical's body (D15). */
static int def_parses(const char *body, st_lnm_def *d, const char **why)
{
    st_jdoc doc;
    char err[64];
    int rc;
    *why = "";
    if (st_json_parse(&doc, body, strlen(body), err, sizeof err)) return -2;
    rc = st_lnm_def_parse(doc.root, d, why);
    st_json_free(&doc);
    return rc;
}

static void test_lnm_def(void)
{
    static st_lnm_def d;
    const char *why;
    char many[2048];
    int i;
    CHECK(st_lnm_mode("user") == ST_LNM_USER && st_lnm_mode("SUPER") == ST_LNM_SUPER &&
          st_lnm_mode("supervisor") == ST_LNM_SUPER && st_lnm_mode("Executive") == ST_LNM_EXEC,
          "modes by name, in any case");
    CHECK(st_lnm_mode("kernel") < 0 && st_lnm_mode("") < 0 && st_lnm_mode("users") < 0,
          "kernel mode and anything else refused");
    CHECK(!strcmp(st_lnm_mode_name(ST_LNM_EXEC), "exec") && !strcmp(st_lnm_mode_name(9), "?"), "mode names");
    CHECK(def_parses("{\"table\":\"lnm$system_table\",\"name\":\"My_Name\",\"mode\":\"exec\","
                     "\"attributes\":[\"confine\"],\"equivalences\":[{\"value\":\"DKA0:[A.]\","
                     "\"attributes\":[\"concealed\",\"terminal\"]},{\"value\":\"B\"}],\"replace\":true}", &d, &why) == 0 &&
          !strcmp(d.table, "LNM$SYSTEM_TABLE") && !strcmp(d.name, "My_Name") && d.mode == ST_LNM_EXEC &&
          d.attrs == ST_LNM_CONFINE && d.replace && d.neq == 2 &&
          d.eq[0].attrs == (ST_LNM_CONCEALED | ST_LNM_TERMINAL) && !strcmp(d.eq[1].value, "B") && !d.eq[1].attrs,
          "a definition: the table upper-cased, the name kept as given, modes and attributes");
    CHECK(def_parses("{\"table\":\"LNM$GROUP\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == 0 &&
          !d.replace && !d.attrs, "replace and attributes are optional");
    CHECK(def_parses("{\"table\":\"LNM$PROCESS_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$JOB_8217EDC0\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1,
          "the process and job tables refused for a define");
    CHECK(def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"kernel\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1 &&
          strstr(why, "mode"), "kernel mode refused");
    CHECK(def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\"}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1,
          "table, name, mode and at least one equivalence required");
    CHECK(def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"a\\nb\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\\u00e9\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[\"Y\"]}", &d, &why) == -1,
          "empty values, control characters, bytes past 7E and bare strings refused");
    CHECK(def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}],\"other\":1}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"attributes\":[\"table\"],\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\",\"attributes\":[\"confine\"]}]}", &d, &why) == -1 &&
          def_parses("{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"replace\":1,\"equivalences\":[{\"value\":\"Y\"}]}", &d, &why) == -1,
          "unknown members and attributes refused, replace must be a boolean");
    st_copy(many, sizeof many, "{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"X\",\"mode\":\"user\",\"equivalences\":[");
    for (i = 0; i < 17; i++) st_append(many, sizeof many, i ? ",{\"value\":\"V\"}" : "{\"value\":\"V\"}");
    st_append(many, sizeof many, "]}");
    CHECK(def_parses(many, &d, &why) == -1, "at most 16 equivalences");
    st_copy(many, sizeof many, "{\"table\":\"LNM$SYSTEM_TABLE\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"Y\"}],\"name\":\"");
    for (i = 0; i < 256; i++) st_append(many, sizeof many, "N");
    st_append(many, sizeof many, "\"}");
    CHECK(def_parses(many, &d, &why) == -1, "a name over 255 characters refused");
}

static void test_logicals(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    const char *body;
    hdr t[2], adm[3];

    call("GET", "/api/v1/logicals", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "logical names need a session");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = NULL;
    call("GET", "/api/v1/logicals/tables", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"your_group_table\":\"LNM$GROUP_000362\"") &&
          strstr(body, "{\"name\":\"LNM$SYSTEM_TABLE\",\"mode\":\"kernel\",\"kind\":\"system\",\"listable\":true}") &&
          strstr(body, "\"kind\":\"cluster\"") && strstr(body, "\"kind\":\"job\"") && !strstr(body, "LNM$FILE_DEV"),
          "the tables: only real tables, by kind; the viewer's group table named");
    CHECK(strstr(body, "\"truncated\":false"), "the tables list says whether it was cut short");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/logicals?table=lnm$system_table&filter=sys$s*", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"protection\":\"(RWC,RWC,R,R)\"") &&
          strstr(body, "{\"name\":\"SYS$SYSROOT\",\"mode\":\"exec\",\"attributes\":[],\"equivalences\":[{\"value\":\"X86VMS$DKA0:[SYS0.]\",\"attributes\":[\"concealed\",\"terminal\"]},{\"value\":\"SYS$COMMON:\",\"attributes\":[]}]}") &&
          !strstr(body, "SYS$COMMON\",\"mode") && !strstr(body, "MOTD"),
          "the names matching a pattern, with modes, attributes and every equivalence");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=motd", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"value\":\"Welcome to \\\"X86VMS\\\"\""),
          "plain text matches anywhere in the name; quotes inside a value survive");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/logicals?table=LNM$GROUP", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"name\":\"LNM$GROUP_000362\"") &&
          strstr(b.resp.body.data, "PROJECT_DATA"), "LNM$GROUP is the viewer's own group table");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$GROUP_000001", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "IVLOGTAB"),
          "another group's table: OpenVMS answers as for no such table (IVLOGTAB, as SHOW LOGICAL does)");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$NO_SUCH_TABLE", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "IVLOGTAB"), "no such table: the same IVLOGTAB");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$PROCESS", t, NULL, &b);
    CHECK(b.resp.status == 400, "the process table is never offered: it would be the service's");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals/LNM$PROCESS_TABLE/STEWARD_GATEWAY_SECRET", t, NULL, &b);
    CHECK(b.resp.status == 400 && !strstr(b.resp.body.data, "secret"), "nor can a name be read from it");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", t, NULL, &b);
    CHECK(b.resp.status == 400, "plain text over 61 characters is refused, not cut short");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=a%2Fb", t, NULL, &b);
    CHECK(b.resp.status == 400, "a filter that is not a name or pattern is refused");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/logicals/LNM$SYSTEM_TABLE/SYS$SYSROOT", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"table\":\"LNM$SYSTEM_TABLE\"") &&
          strstr(body, "\"translations\":[[],[{\"name\":\"SYS$COMMON\",\"table\":\"LNM$SYSTEM_TABLE\",\"value\":\"X86VMS$DKA0:[SYS0.SYSCOMMON.]\",\"attributes\":[\"concealed\",\"terminal\"]}]]"),
          "one name: a terminal equivalence stops; SYS$COMMON: is translated in turn");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals/LNM$GROUP/PROJECT_LOG", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"table\":\"LNM$GROUP_000362\"") &&
          strstr(b.resp.body.data, "\"name\":\"PROJECT_DATA\",\"table\":\"LNM$GROUP_000362\""),
          "a group name, translated through the viewer's group table");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals/LNM$SYSTEM/MOTD", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOLOGTAB"),
          "one name by a search-list alias (LNM$SYSTEM): NOLOGTAB, as on OpenVMS");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals/LNM$SYSTEM_TABLE/NO_SUCH_NAME", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOLOGNAM"), "no such name: OpenVMS's NOLOGNAM");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$GROUP_000001", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "SYSTEM_TOOLS"), "with SYSPRV another group's table is read");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- access history (Phase 6) */

static void test_access(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65], uri[160];
    const char *body, *p, *q;
    long long now = st_plat_time();
    hdr t[2], adm[3];

    call("GET", "/api/v1/access", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "access history needs a session");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = NULL;
    call("GET", "/api/v1/access", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"accounting\":{\"read\":false,\"vms_status\":\"%X0001829A\"") &&
          strstr(body, "\"live\":{\"read\":true}"),
          "without privilege each file source is refused by name, with OpenVMS's status; the live list is still read");
    CHECK(!strstr(body, "\"source\":\"accounting\"") && !strstr(body, "\"user\":\"SYSTEM\""),
          "nothing from a refused source, and no one else's processes without WORLD");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && !strstr(body, "\"read\":false"), "with SYSPRV every source is read");
    CHECK(strstr(body, "\"kind\":\"breakin\"") && strstr(body, "\"route\":\"Steward\"") &&
          strstr(body, "\"route\":\"batch\""), "the day's sessions, failures and break-ins, by route");
    /* newest first */
    p = strstr(body, "\"start\":");
    q = p ? strstr(p + 1, "\"start\":") : NULL;
    CHECK(p && q && strtoll(p + 8, NULL, 10) >= strtoll(q + 8, NULL, 10), "newest first");
    CHECK(strstr(body, "\"truncated\":false") != NULL, "nothing cut off");
    CHECK(!strstr(body, "\"complete\""), "and every source read to the end");
    st_resp_free(&b.resp);
    snprintf(uri, sizeof uri, "/api/v1/access?since=%lld", now - 40 * 86400);
    call("GET", uri, adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"ssh\":{\"read\":true,\"complete\":false}") &&
          strstr(b.resp.body.data, "\"accounting\":{\"read\":true}"),
          "SSH logs stopped at their budget: read, but not complete, and only that source");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/access?outcome=failure&user=root", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"user\":\"ROOT\"") && !strstr(body, "\"kind\":\"session\"") &&
          !strstr(body, "\"user\":\"ADMIN\""), "filtered by outcome and user");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access?route=steward", adm, NULL, &b);
    CHECK(b.resp.status == 200 && !strstr(b.resp.body.data, "\"route\":\"SSH\"") &&
          strstr(b.resp.body.data, "\"route\":\"Steward\""), "and by route, ignoring case");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access?limit=2", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"truncated\":true"), "a limit cuts the list and says so");
    st_resp_free(&b.resp);
    snprintf(uri, sizeof uri, "/api/v1/access?since=%lld&until=%lld", now - 2000, now - 1000);
    call("GET", uri, adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"start\":") && !strstr(b.resp.body.data, "\"route\":\"Steward\""),
          "a time window");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/access?since=abc", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a bad time is refused");
    st_resp_free(&b.resp);
    snprintf(uri, sizeof uri, "/api/v1/access?since=%lld&until=%lld", now, now - 10);
    call("GET", uri, adm, NULL, &b);
    CHECK(b.resp.status == 400, "since after until is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access?outcome=everything", adm, NULL, &b);
    CHECK(b.resp.status == 400, "an unknown outcome is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access?limit=0", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a limit of 0 is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/access?user=a%22b", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a filter with a quote is refused");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ------------------------------------------------- create, copy, delete (Phase 4) */

static void test_create(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65], etag[48];
    hdr t[3], adm[4];

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf;
    adm[2].n = NULL; adm[3].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"SYSPRV\"]}", &b);
    st_resp_free(&b.resp);

    call("GET", "/api/v1/uic/next?group=362", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"uic\":\"[362,5]\""),
          "the next free member of a UIC group, from the rights database");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/users", t, "{\"username\":\"steward_new\",\"uic\":\"[362,10]\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 403 && (strstr(b.resp.body.data, "NOSYSPRV") || strstr(b.resp.body.data, "RMS-E-PRV")),
          "an unprivileged user cannot create one: OpenVMS refuses (reading the template, before SYSUAF)");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 422, "username, uic and password are required");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"uic\":\"[362,177777]\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 422, "a group identifier's UIC is not a user's");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"uic\":\"[362,10]\",\"password\":\"a-long-enough-pass\",\"shoe\":1}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "shoe"), "unknown members are refused");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"uic\":\"[362,10]\",\"password\":\"short\"}", &b);
    CHECK(b.resp.status == 422 && strstr(b.resp.body.data, "INVPWDLEN"), "a password below the template's minimum is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_NEW", adm, NULL, &b);
    CHECK(b.resp.status == 404, "and nothing was left behind");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"uic\":\"[362,1]\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 409, "a UIC already in use is refused");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/users", adm,
         "{\"username\":\"steward_new\",\"uic\":\"[362,10]\",\"password\":\"a-long-enough-pass\","
         "\"owner\":\"New starter\",\"flags\":[],\"default_directory\":\"[STEWARD_NEW]\"}", &b);
    etag_of(&b, etag, sizeof etag);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"username\":\"STEWARD_NEW\",\"owner\":\"New starter\"") &&
          strstr(b.resp.body.data, "\"uic\":\"[362,10]\",\"flags\":[]") &&
          strstr(b.resp.body.data, "\"default_directory\":\"[STEWARD_NEW]\"") &&
          strstr(b.resp.body.data, "\"pre_expired\":true") && strlen(etag) == 34,
          "create from DEFAULT: the fields given, DISUSER cleared, pre-expired, with an ETag");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers/STEWARD_NEW", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"value\":\"[362,10]\""), "with its UIC identifier, as AUTHORIZE ADD");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm,
         "{\"username\":\"steward_dir\",\"uic\":\"[362,12]\",\"password\":\"a-long-enough-pass\",\"create_directory\":true}", &b);
    CHECK(b.resp.status == 201 && strstr(st_buf_cstr(&b.resp.headers), "X-Steward-Warning: no directory was created: the account has no default device"),
          "no directory without a default device (DEFAULT has none): the user is made, with a warning");
    st_resp_free(&b.resp);
    {
        char et[48];
        call("GET", "/api/v1/users/STEWARD_DIR", adm, NULL, &b);
        etag_of(&b, et, sizeof et);
        st_resp_free(&b.resp);
        adm[2].n = "HTTP_IF_MATCH"; adm[2].v = et;
        call("DELETE", "/api/v1/users/STEWARD_DIR", adm, NULL, &b);
        adm[2].n = NULL;
    }
    st_resp_free(&b.resp);
    call("POST", "/api/v1/users", adm, "{\"username\":\"steward_new\",\"uic\":\"[362,11]\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 409, "an existing username is a conflict");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/session", NULL, "{\"username\":\"steward_new\",\"password\":\"a-long-enough-pass\"}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "password-expired"), "the new user must change the password first");
    st_resp_free(&b.resp);

    call("POST", "/api/v1/users", adm,
         "{\"username\":\"steward_copy\",\"uic\":\"[362,11]\",\"password\":\"a-long-enough-pass\",\"template\":\"steward_adm\"}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"owner\":\"Steward administrator\""),
          "copy: the source's fields, as AUTHORIZE COPY");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_COPY/identifiers", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"identifiers\":[]"), "without its identifiers, as AUTHORIZE COPY");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_COPY", adm, NULL, &b);
    etag_of(&b, etag, sizeof etag);
    st_resp_free(&b.resp);
    adm[2].n = "HTTP_IF_MATCH"; adm[2].v = etag;
    call("DELETE", "/api/v1/users/STEWARD_COPY", adm, NULL, &b);
    CHECK(b.resp.status == 204, "delete the copy");
    st_resp_free(&b.resp);
    adm[2].n = NULL;
    call("POST", "/api/v1/users", adm,
         "{\"username\":\"steward_copy\",\"uic\":\"[362,11]\",\"password\":\"a-long-enough-pass\",\"template\":\"steward_adm\",\"copy_identifiers\":true}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/users/STEWARD_COPY/identifiers", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "STEWARD_DEMO") && strstr(b.resp.body.data, "STEWARD_OPS"),
          "or with them, when asked");
    st_resp_free(&b.resp);

    call("DELETE", "/api/v1/users/STEWARD_NEW", adm, NULL, &b);
    CHECK(b.resp.status == 428, "a delete needs If-Match");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/users/STEWARD_ADM", adm, NULL, &b);
    CHECK(b.resp.status == 409, "you cannot delete the account you are signed in as");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/users/STEWARD", adm, NULL, &b);
    CHECK(b.resp.status == 409, "nor the service account");
    st_resp_free(&b.resp);
    adm[2].n = "HTTP_IF_MATCH"; adm[2].v = "\"00000000000000000000000000000000\"";
    call("DELETE", "/api/v1/users/STEWARD_NEW", adm, NULL, &b);
    CHECK(b.resp.status == 412, "nor an account changed since you looked at it");
    st_resp_free(&b.resp);
    adm[2].n = NULL;
    {
        const char *names[] = { "STEWARD_NEW", "STEWARD_COPY" };
        int i;
        for (i = 0; i < 2; i++) {
            char path[64];
            snprintf(path, sizeof path, "/api/v1/users/%s", names[i]);
            call("GET", path, adm, NULL, &b);
            etag_of(&b, etag, sizeof etag);
            st_resp_free(&b.resp);
            adm[2].n = "HTTP_IF_MATCH"; adm[2].v = etag;
            call("DELETE", path, adm, NULL, &b);
            CHECK(b.resp.status == 204, "delete");
            st_resp_free(&b.resp);
            adm[2].n = NULL;
            call("GET", path, adm, NULL, &b);
            CHECK(b.resp.status == 404, "and it is gone");
            st_resp_free(&b.resp);
        }
    }
    call("GET", "/api/v1/identifiers/STEWARD_NEW", adm, NULL, &b);
    CHECK(b.resp.status == 404, "with its UIC identifier");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/identifiers/STEWARD_DEMO/holders", adm, NULL, &b);
    CHECK(b.resp.status == 200 && !strstr(b.resp.body.data, "STEWARD_COPY"), "and its holdings, as AUTHORIZE REMOVE");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

static void test_gateway(void)
{
    st_app_config cfg;
    result a;
    hdr good[2], bad[2];
    cfg.idle_secs = 900; cfg.absolute_secs = 28800; cfg.cookie_secure = 1;
    cfg.trusted_proxies = "";
    cfg.gateway_secret = "unit-test-gateway-secret-not-a-real-one";
    st_app_init(&cfg);
    good[0].n = "HTTP_X_STEWARD_GATEWAY"; good[0].v = cfg.gateway_secret; good[1].n = NULL;
    bad[0].n = "HTTP_X_STEWARD_GATEWAY"; bad[0].v = "unit-test-gateway-secret-not-a-real-onX"; bad[1].n = NULL;
    call("GET", "/api/v1/health", NULL, NULL, &a);
    CHECK(a.resp.status == 403, "without the gateway secret a request is refused (direct FastCGI access)");
    st_resp_free(&a.resp);
    call("GET", "/api/v1/health", bad, NULL, &a);
    CHECK(a.resp.status == 403, "a wrong gateway secret is refused");
    st_resp_free(&a.resp);
    call("GET", "/api/v1/health", good, NULL, &a);
    CHECK(a.resp.status == 200, "with the gateway secret it is served");
    st_resp_free(&a.resp);
    cfg.gateway_secret = "";
    st_app_init(&cfg);
}

/* Phase 7b (D15): define and deassign through the dispatcher, on the stub. */
static void test_logical_changes(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    const char *body;
    hdr t[3], adm[3], nocsrf[2];
    static const char *sys_user = "{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"STEWARD_7B\",\"mode\":\"user\","
                                  "\"equivalences\":[{\"value\":\"FIRST\"}]}";

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("PUT", "/api/v1/logical", t, "{\"table\":\"LNM$GROUP\",\"name\":\"MINE\",\"mode\":\"user\",\"equivalences\":[{\"value\":\"X\"}]}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"), "no privilege: OpenVMS's NOPRIV for the group table");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    nocsrf[0].n = "HTTP_COOKIE"; nocsrf[0].v = ac; nocsrf[1].n = NULL;
    call("PUT", "/api/v1/logical", nocsrf, sys_user, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "csrf"), "a define needs the CSRF header");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"STEWARD_7B\",\"mode\":\"exec\","
                                       "\"equivalences\":[{\"value\":\"X\"}]}", &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOSYSNAM"),
          "executive mode without SYSNAM: refused, not quietly made user mode");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B", adm, NULL, &b);
    CHECK(b.resp.status == 404, "and nothing was defined");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/logical", adm, sys_user, &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"modes\":[\"user\"]") &&
          strstr(b.resp.body.data, "\"value\":\"FIRST\""), "SYSPRV: a user-mode name in the system table, read back");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, sys_user, &b);
    CHECK(b.resp.status == 409, "defining it again without replace: 409");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, "{\"table\":\"lnm$system_table\",\"name\":\"STEWARD_7B\",\"mode\":\"user\",\"replace\":true,"
                                       "\"attributes\":[\"no_alias\"],\"equivalences\":[{\"value\":\"DKA0:[A.]\",\"attributes\":[\"concealed\",\"terminal\"]},"
                                       "{\"value\":\"say \\\"hi\\\"\"}]}", &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"mode\":\"user\",\"attributes\":[\"no_alias\"]") &&
          strstr(body, "{\"value\":\"DKA0:[A.]\",\"attributes\":[\"concealed\",\"terminal\"]},{\"value\":\"say \\\"hi\\\"\",\"attributes\":[]}"),
          "with replace: 200, attributes and a quoted value read back as given");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\",\"sysnam\"]}", &b);
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"STEWARD_7B\",\"mode\":\"exec\","
                                       "\"equivalences\":[{\"value\":\"INNER\"}]}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"modes\":[\"user\",\"exec\"]"),
          "with SYSNAM: executive mode, beside the user-mode name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=exec", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"mode\":\"exec\"") &&
          strstr(b.resp.body.data, "\"value\":\"INNER\""), "read at a mode: the executive-mode definition, not the outermost");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=super", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOLOGNAM"), "read at a mode it is not at: NOLOGNAM");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=kernel", adm, NULL, &b);
    CHECK(b.resp.status == 400, "read at kernel mode: refused as a parameter");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=STEWARD_7B", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"mode\":\"user\"") && !strstr(body, "INNER"),
          "listed once, at its outermost mode, as SHOW LOGICAL lists it");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$SYSTEM_TABLE\",\"name\":\"STEWARD_7B\",\"mode\":\"super\","
                                       "\"attributes\":[\"no_alias\"],\"equivalences\":[{\"value\":\"S\"}]}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"modes\":[\"super\",\"exec\"]"),
          "no_alias at supervisor mode: the user-mode name goes, as OpenVMS does it");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, sys_user, &b);
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=super", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"removed\":[\"user\",\"super\"]"),
          "deassign at supervisor mode removes it and the outer user-mode name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"value\":\"INNER\"") &&
          strstr(b.resp.body.data, "\"modes\":[\"exec\"]"), "the executive-mode name is left");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=kernel", adm, NULL, &b);
    CHECK(b.resp.status == 400, "kernel mode is refused for a deassign");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=exec", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"removed\":[\"exec\"]"), "deassign at executive mode");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=STEWARD_7B&mode=user", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOLOGNAM"), "deassigning what is gone: NOLOGNAM");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$GROUP\",\"name\":\"A/B\",\"mode\":\"user\","
                                       "\"equivalences\":[{\"value\":\"C\"}]}", &b);
    CHECK(b.resp.status == 201 && strstr(b.resp.body.data, "\"table\":\"LNM$GROUP_000362\""),
          "LNM$GROUP is the viewer's group table for a define too");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/logical?table=LNM$GROUP_000362&name=A%2FB", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"name\":\"A/B\""), "a name with / is reached by query");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$GROUP&name=A%2FB&mode=user", adm, NULL, &b);
    CHECK(b.resp.status == 200, "and deassigned");
    st_resp_free(&b.resp);

    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$SYSTEM_DIRECTORY\",\"name\":\"X\",\"mode\":\"user\","
                                       "\"equivalences\":[{\"value\":\"C\"}]}", &b);
    CHECK(b.resp.status == 404, "never in the directory");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/logical", adm, "{\"table\":\"LNM$PROCESS_TABLE\",\"name\":\"X\",\"mode\":\"user\","
                                       "\"equivalences\":[{\"value\":\"C\"}]}", &b);
    CHECK(b.resp.status == 422, "never in the process table");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$JOB_8210AE00&name=SYS$LOGIN&mode=user", adm, NULL, &b);
    CHECK(b.resp.status == 400, "nor deassigned from a job table");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=MOTD", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a deassign needs a mode");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Phase 8 (D16): processes. */
static void test_processes(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    const char *body;
    hdr t[3], adm[3];
    unsigned int pid = 0;

    CHECK(st_parse_pid("0000751A", &pid) && pid == 0x751A && st_parse_pid("%X0000751a", &pid) && pid == 0x751A,
          "a PID: 8 hex digits, with or without %X, either case");
    CHECK(!st_parse_pid("751A", &pid) && !st_parse_pid("0000751G", &pid) && !st_parse_pid("00000000", &pid) &&
          !st_parse_pid("0000751A0", &pid) && !st_parse_pid("", &pid), "short, non-hex, zero and long PIDs refused");
    CHECK(!st_parse_pid("FFFFFFFF", &pid) && !st_parse_pid("%Xffffffff", &pid), "FFFFFFFF refused: to $GETJPI and $DELPRC it is the wildcard");
    {
        char img[64];
        st_proc_image_name("X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]steward.exe;1", img, sizeof img);
        CHECK(!strcmp(img, "STEWARD.EXE"), "an image's name and type, upper case, without directory or version");
        st_proc_image_name("", img, sizeof img);
        CHECK(!strcmp(img, ""), "no image: empty");
        st_proc_image_name("DKA0:<A.B>X.EXE", img, 4);
        CHECK(!strcmp(img, "X.E"), "cut to the buffer");
    }
    CHECK(!strcmp(st_proc_state_name(5), "LEF") && !strcmp(st_proc_state_name(14), "CUR") &&
          !strcmp(st_proc_state_name(0), "?") && !strcmp(st_proc_state_name(15), "?"), "state names, SCH$C_ 1 to 14");
    CHECK(!strcmp(st_proc_kind(3, 0), "interactive") && !strcmp(st_proc_kind(2, 0), "batch") &&
          !strcmp(st_proc_kind(1, 0), "network") && !strcmp(st_proc_kind(0, 0), "detached") &&
          !strcmp(st_proc_kind(3, 1), "subprocess"), "process kinds from JPI$_MODE and the owner");

    call("GET", "/api/v1/processes", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "processes need a session");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/processes", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"pid\":\"00007520\"") && strstr(body, "\"pid\":\"00007521\"") &&
          !strstr(body, "00007500") && !strstr(body, "\"SYSTEM\"") && !strstr(body, "WEBMASTER"),
          "no privileges: only the viewer's own processes, as OpenVMS shows them");
    CHECK(strstr(body, "\"state\":\"LEF\"") && strstr(body, "\"kind\":\"subprocess\"") &&
          strstr(body, "\"uic\":\"[362,1]\"") && strstr(body, "\"cpu_ms\":350"), "state, kind, UIC and CPU in the list");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/00007500", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"), "another's process: NOPRIV, as SHOW PROCESS/ID");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/0000FFF0", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NONEXPR"), "no such process: NONEXPR");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/7520", t, NULL, &b);
    CHECK(b.resp.status == 400, "a PID not in OpenVMS's form is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/%25X00007520", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"master\":\"00007520\"") && strstr(body, "\"rights\":[\"STEWARD_OPS\"]") &&
          strstr(body, "\"astlm\":{\"limit\":300,\"left\":270}") && strstr(body, "\"current_privileges\":[\"TMPMBX\",\"NETMBX\"]"),
          "one process: master, rights, quotas and privileges");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"group\"]}", &b);
    CHECK(b.resp.status == 200, "STEWARD_ADM switches GROUP on");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "00007500") && strstr(body, "00007520") &&
          !strstr(body, "\"SYSTEM\"") && !strstr(body, "WEBMASTER"), "with GROUP: the group's processes, Steward's pool among them");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"world\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes?filter=steward_1*", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "00007500") && strstr(body, "00007501") && !strstr(body, "00007520"),
          "with WORLD, filtered by a pattern on the process name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes?filter=webmaster", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "00007530") && strstr(b.resp.body.data, "\"truncated\":false"),
          "and by username");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes?filter=a%22b", adm, NULL, &b);
    CHECK(b.resp.status == 400, "a filter with a quote is refused");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Phase 8b (D16): stopping a process. Runs after test_processes: it changes the stub. */
static void test_process_stop(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    hdr t[3], adm[3], nocsrf[2];

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    nocsrf[0].n = "HTTP_COOKIE"; nocsrf[0].v = tc; nocsrf[1].n = NULL;
    call("DELETE", "/api/v1/processes/00007521", nocsrf, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "csrf"), "a stop needs the CSRF header");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007500", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"), "another's process: NOPRIV, as STOP/ID");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007502", t, NULL, &b);
    CHECK(b.resp.status == 403, "a worker busy with the viewer's own request: not theirs to stop (its real owner is the pool)");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/751", t, NULL, &b);
    CHECK(b.resp.status == 400, "a PID not in OpenVMS's form is refused");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007521", t, NULL, &b);
    CHECK(b.resp.status == 202 && strstr(b.resp.body.data, "\"name\":\"_FTA12:_S1\"") && strstr(b.resp.body.data, "\"stopping\":true"),
          "its own process: stopped, 202");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/00007521", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NONEXPR"), "and gone");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"group\"]}", &b);
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007500", adm, NULL, &b);
    CHECK(b.resp.status == 409 && strstr(b.resp.body.data, "steward-process"),
          "Steward's own pool process: refused, though GROUP would allow it");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/00007500", adm, NULL, &b);
    CHECK(b.resp.status == 200, "and still there");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007502", adm, NULL, &b);
    CHECK(b.resp.status == 409, "a pool worker busy with STEWARD_TEST's request (reported under that name): refused by its image");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007530", adm, NULL, &b);
    CHECK(b.resp.status == 403, "another group's process with GROUP only: NOPRIV");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"world\"]}", &b);
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007502", adm, NULL, &b);
    CHECK(b.resp.status == 409, "and with WORLD");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/0000040B", adm, NULL, &b);
    CHECK(b.resp.status == 409 && strstr(b.resp.body.data, "system-process"),
          "a system process (OPCOM, [1,4]): refused with WORLD, as the user decided after the 8b check");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/processes/0000040B", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"system\":true"), "still there, and marked a system process");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007530", adm, NULL, &b);
    CHECK(b.resp.status == 202, "with WORLD: stopped");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/processes/00007530", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NONEXPR"), "stopping it again: NONEXPR");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Phase 9 (D17): queues, read-only. */
static void test_queues(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65], out[64], names[200];
    const char *body;
    hdr t[3], adm[3];
    unsigned int n = 0;

    CHECK(st_valid_queue_name("sys$batch", out) && !strcmp(out, "SYS$BATCH") && !st_valid_queue_name("SYS*", out) &&
          !st_valid_queue_name("", out) && !st_valid_queue_name("A B", out), "queue names: upper-cased, no wildcards");
    CHECK(st_parse_entry("269", &n) && n == 269 && !st_parse_entry("0", &n) && !st_parse_entry("1234567890", &n) &&
          !st_parse_entry("12a", &n), "entry numbers: 1 to 9 digits, not 0");
    st_queue_status_names(0x1000 | 0x40000, names, sizeof names);
    CHECK(!strcmp(names, "stopped,available"), "queue status bits by name");
    st_job_status_names(0x4 | 0x8, names, sizeof names);
    CHECK(!strcmp(names, "holding,inaccessible"), "job status bits by name");
    {
        char t[8][32], many[300];
        int i;
        CHECK(st_queue_target_list("X86VMS_BATCH", 12, t, 8) == 1 && !strcmp(t[0], "X86VMS_BATCH"),
              "generic targets: one bare name, as x86 gives it");
        CHECK(st_queue_target_list("A_BATCH,B_BATCH", 15, t, 8) == 2 && !strcmp(t[1], "B_BATCH") &&
              st_queue_target_list("A_BATCH B_BATCH", 15, t, 8) == 2 &&
              st_queue_target_list("A_BATCH\0B_BATCH\0\0", 17, t, 8) == 2 && !strcmp(t[1], "B_BATCH"),
              "several: commas, spaces or NULs between them");
        CHECK(st_queue_target_list("", 0, t, 8) == 0, "none: an execution queue feeds nothing");
        many[0] = '\0';
        for (i = 0; i < 9; i++) st_append(many, sizeof many, i ? ",Q" : "Q");
        CHECK(st_queue_target_list(many, strlen(many), t, 8) == -1, "more than fit: cannot tell (-1), never a short list");
        CHECK(st_queue_target_list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", 33, t, 8) == -1, "a name too long: cannot tell");
    }

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/queues", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"name\":\"SYS$BATCH\",\"kind\":\"batch\",\"generic\":true") &&
          strstr(body, "\"name\":\"LPA0_PRINT\",\"kind\":\"output\",\"generic\":false,\"status\":[\"stopped\"]") &&
          strstr(body, "\"executing\":1,\"pending\":1"), "every queue, kind, status and counts");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/queues/x86vms_batch", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "{\"entry\":141,\"accessible\":false,\"name\":\"\",\"username\":\"\",\"status\":[\"executing\"]") &&
          strstr(body, "{\"entry\":272,\"accessible\":true,\"name\":\"REPORT\",\"username\":\"STEWARD_ADM\"") &&
          strstr(body, "\"name\":\"X86VMS_BATCH\""), "a queue's jobs: another group's inaccessible, the group's shown (G:R)");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/141", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"), "an inaccessible job by entry: NOPRIV");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/269", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"name\":\"NIGHTLY\"") && strstr(body, "\"status\":[\"holding\"]") &&
          strstr(body, "\"files\":[\"SYS$SYSDEVICE:[STEWARD_TEST]NIGHTLY.COM;1\"]") && strstr(body, "\"uic\":\"[362,1]\""),
          "one's own job: name, status, files, UIC");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/999", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOSUCHENT"), "no such entry: NOSUCHENT, as on OpenVMS");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/queues/NO_SUCH", t, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "NOSUCHQUE"), "no such queue: NOSUCHQUE");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/queues/SYS*", t, NULL, &b);
    CHECK(b.resp.status == 400, "a wildcard queue name is refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/0", t, NULL, &b);
    CHECK(b.resp.status == 400, "entry 0 is refused");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/141", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"name\":\"BZSOAK\""), "with SYSPRV, anyone's job");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

void st_plat_stub_startup_unknown(int on);   /* st_plat_stub.c, tests only */

/* Phase 9b (D17): job and queue changes. Runs after test_queues: it changes the stub. */
static void test_queue_changes(void)
{
    result b;
    char tc[140], ac[140], tcsrf[65], acsrf[65];
    hdr t[3], adm[3], nocsrf[2];

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    nocsrf[0].n = "HTTP_COOKIE"; nocsrf[0].v = tc; nocsrf[1].n = NULL;
    call("POST", "/api/v1/jobs/269/release", nocsrf, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "csrf"), "a job change needs the CSRF header");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/jobs/269/release", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"done\":\"released\""), "its own held job: released");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/269", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"status\":[\"pending\"]"), "and pending");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/jobs/269/hold", t, NULL, &b);
    CHECK(b.resp.status == 200, "held again");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/jobs/141", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "NOPRIV"), "another's job: JBC NOPRIV, as DELETE/ENTRY");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/X86VMS_BATCH/stop", t, NULL, &b);
    CHECK(b.resp.status == 409 && strstr(b.resp.body.data, "startup-queue"), "a queue SYS$BATCH feeds: refused, whoever asks");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/LPA0_PRINT/start", t, NULL, &b);
    CHECK(b.resp.status == 403, "starting a queue without SYSPRV: NOPRIV");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("POST", "/api/v1/jobs/269/release", adm, NULL, &b);
    CHECK(b.resp.status == 403, "its group's job: may read, not change (as the queue manager decides)");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("POST", "/api/v1/jobs/141/hold", adm, NULL, &b);
    CHECK(b.resp.status == 409 && strstr(b.resp.body.data, "EXECUTING"), "holding an executing job: JBC EXECUTING, 409");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/SYS$BATCH/stop", adm, NULL, &b);
    CHECK(b.resp.status == 409, "SYS$BATCH: refused with SYSPRV too");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/LPA0_PRINT/start", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"status\":[\"available\"]"), "with SYSPRV: a stopped queue started");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/LPA0_PRINT/stop", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"status\":[\"stopped\"]"), "and stopped again");
    st_resp_free(&b.resp);

    /* If the start-up queues cannot be read, no queue is stopped (fail closed). */
    st_plat_stub_startup_unknown(1);
    call("POST", "/api/v1/queues/LPA0_PRINT/stop", adm, NULL, &b);
    CHECK(b.resp.status == 503 && strstr(b.resp.body.data, "startup-queues-unknown"),
          "start-up queues unknown: every stop refused (503), even of a print queue");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/queues/LPA0_PRINT/start", adm, NULL, &b);
    CHECK(b.resp.status == 200, "starting is never refused");
    st_resp_free(&b.resp);
    st_plat_stub_startup_unknown(0);
    call("POST", "/api/v1/queues/LPA0_PRINT/stop", adm, NULL, &b);
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/jobs/141", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"done\":\"deleted\""), "with SYSPRV: another's job deleted");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/jobs/141", adm, NULL, &b);
    CHECK(b.resp.status == 404, "and gone");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Phase 10 (D18): the SYSGEN SHOW/ALL parser and the endpoint. */
typedef struct { st_param p[8]; int n; } sysgen_got;
static int sysgen_keep(const st_param *p, void *ctx)
{
    sysgen_got *g = ctx;
    if (g->n < 8) g->p[g->n++] = *p;
    return 0;
}

static void test_sysgen(void)
{
    static const char *const lines[] = {
        "", "Parameters in use: Active",
        "Parameter Name            Current    Default     Min.       Max.   Unit  Dynamic\r",
        "--------------            -------    -------   -------    -------  ----  -------",
        "GBLPAGES                 11390868    8388608   8388608         -1 Pagelets   D",
        " internal value            711930     524288    524288         -1 Pages      D",
        "SCSNODE                 \"X86VMS  \"    \"    \"    \"    \"     \"ZZZZ\" Ascii       ",
        "DISK_QUORUM     \"                \"    \"    \"    \"    \"     \"ZZZZ\" Ascii       ",
        "SCH_SOFT_OFFLD         (none set) (none set)         0       1023 CPU bitmap D",
        "MAXPROCESSCNT                 916         32        12      32767 Processes  ",
        "%SYSGEN-W-SOMETHING, a message", NULL };
    sysgen_got g;
    st_sysgen_parser p;
    result b;
    char tc[140], tcsrf[65];
    const char *body;
    hdr t[3];
    int i;

    memset(&g, 0, sizeof g);
    st_sysgen_init(&p, sysgen_keep, &g);
    for (i = 0; lines[i]; i++) st_sysgen_line(&p, lines[i], strlen(lines[i]));
    st_sysgen_end(&p);
    CHECK(g.n == 5, "five parameters; headings, rules and messages skipped");
    CHECK(!strcmp(g.p[0].name, "GBLPAGES") && !strcmp(g.p[0].v.current, "11390868") && !strcmp(g.p[0].v.max, "-1") &&
          !strcmp(g.p[0].v.unit, "Pagelets") && g.p[0].dynamic && g.p[0].has_internal &&
          !strcmp(g.p[0].internal.current, "711930") && !strcmp(g.p[0].internal.unit, "Pages"),
          "a number by column, its unit, dynamic, and its internal value");
    CHECK(!strcmp(g.p[1].name, "SCSNODE") && g.p[1].ascii && !strcmp(g.p[1].v.current, "X86VMS") &&
          !strcmp(g.p[1].v.dflt, "") && !strcmp(g.p[1].v.max, "ZZZZ") && !g.p[1].dynamic,
          "a string parameter: without its quotes and padding");
    CHECK(!strcmp(g.p[2].name, "DISK_QUORUM") && !strcmp(g.p[2].v.current, "") && !strcmp(g.p[2].v.max, "ZZZZ"),
          "a long blank string where the name column is short");
    CHECK(!strcmp(g.p[3].v.current, "(none set)") && !strcmp(g.p[3].v.unit, "CPU bitmap") && g.p[3].dynamic,
          "values and units with blanks in them");
    CHECK(!strcmp(g.p[4].v.unit, "Processes") && !g.p[4].dynamic, "not dynamic: no D");

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/sysgen", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "{\"name\":\"MAXPROCESSCNT\",\"current\":\"916\",\"default\":\"32\",\"min\":\"12\",\"max\":\"32767\",\"unit\":\"Processes\",\"dynamic\":false,\"ascii\":false}") &&
          strstr(body, "\"internal\":{\"current\":") && strstr(body, "\"truncated\":false"), "every parameter, as SYSGEN shows it");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/sysgen?filter=scs*", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"SCSNODE\"") && !strstr(body, "MAXPROCESSCNT"), "filtered by a pattern");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/sysgen?filter=a%22b", t, NULL, &b);
    CHECK(b.resp.status == 400, "a filter with a quote is refused");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Phase 11 (D19): the licence listings' parser and the endpoint. */
typedef struct { st_license l[6]; int n; } lic_got;
static int lic_keep(const st_license *l, void *ctx)
{
    lic_got *g = ctx;
    if (g->n < 6) g->l[g->n++] = *l;
    return 0;
}

static void test_licenses(void)
{
    static const char *const lines[] = {
        "stray line before any part",
        "%%PART%% LOADED", "Active licenses on node X86VMS:", "",
        "BASIC", "\tProducer: VSI", "\tUnits: 0", "\tTermination Date: 30-APR-2027", "\tAvailability: 0  ",
        "\tActivity: 1  ", "\tX86_64",
        "%SHOW-I-SOMETHING, a message",
        "FMS\r", "\tProducer: VSI", "\tPer Core License", "\tReserved: NODEA", "\tX86_64", "\tPCL",
        "%%STATUS%% 00000001",
        "%%PART%% CHARGE", "", "Type: PCL,   Units Required: 2  (X86_64 Per Core)", "%%STATUS%% 10000001",
        "%%PART%% DATABASE", "License Management Facility  V2.0", "  ",
        "License Database File:       SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB;1", "Created by user:             SYSTEM",
        "-----------------------------------",
        "Issuer:                      VSI", "Authorization:               ISV-EXAMPLE-1", "Product Name:                C",
        "PAK Termination Date:        30-APR-2027", "Options:                     X86_64, PCL", "Hardware ID:", "  ",
        "Reserved:                    NODEA", "                             NODEB",
        "Status:                      Disabled", "Modified on:                 15-APR-2026 15:22:29.19",
        "[End Of List]", "%%STATUS%% 00000001", NULL };
    lic_got g;
    st_license_parser p;
    result b;
    char tc[140], tcsrf[65], ac[140], acsrf[65];
    const char *body;
    hdr t[3], adm[3];
    int i;

    memset(&g, 0, sizeof g);
    st_license_init(&p, lic_keep, &g);
    for (i = 0; lines[i]; i++) st_license_line(&p, lines[i], strlen(lines[i]));
    st_license_end(&p);
    CHECK(g.n == 3, "two loaded licences and one PAK; messages and stray lines skipped");
    CHECK(!strcmp(p.node, "X86VMS"), "the node");
    CHECK(g.l[0].part == ST_LIC_LOADED && !strcmp(g.l[0].product, "BASIC") && !strcmp(g.l[0].producer, "VSI") &&
          !strcmp(g.l[0].termination, "30-APR-2027") && !strcmp(g.l[0].availability, "0") &&
          !strcmp(g.l[0].activity, "1") && !strcmp(g.l[0].options, "X86_64") && !g.l[0].per_core,
          "a loaded licence: its fields, trailing blanks gone, the options line");
    CHECK(!strcmp(g.l[1].product, "FMS") && g.l[1].per_core && !strcmp(g.l[1].options, "X86_64, PCL") &&
          g.l[1].nother == 1 && !strcmp(g.l[1].other_label[0], "Reserved") && !strcmp(g.l[1].other_value[0], "NODEA"),
          "per core, two options lines, and a field without a name of its own kept");
    CHECK(g.l[2].part == ST_LIC_DATABASE && !strcmp(g.l[2].product, "C") && !strcmp(g.l[2].authorization, "ISV-EXAMPLE-1") &&
          !strcmp(g.l[2].termination, "30-APR-2027") && !strcmp(g.l[2].hardware_id, "") &&
          !strcmp(g.l[2].status, "Disabled") && !strcmp(g.l[2].modified_on, "15-APR-2026 15:22:29.19"),
          "a PAK: label to the first colon, times kept whole, an empty hardware ID");
    CHECK(g.l[2].nother == 1 && !strcmp(g.l[2].other_value[0], "NODEA, NODEB"), "an indented line continues the field above");
    CHECK(!strcmp(p.db_file, "SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB;1") && !strcmp(p.db_created_by, "SYSTEM"),
          "the database's header");
    CHECK(p.ncharge == 1 && !strcmp(p.charge_type, "PCL") && !strcmp(p.charge_units, "2"), "the charge");
    CHECK(st_license_ok(&p, ST_LIC_LOADED) && st_license_ok(&p, ST_LIC_CHARGE) && p.status[ST_LIC_CHARGE] == 1 &&
          st_license_ok(&p, ST_LIC_DATABASE), "each part's status, without DCL's message-shown bit");

    st_license_init(&p, lic_keep, &g);
    st_license_line(&p, "%%PART%% DATABASE", 17);
    st_license_line(&p, "%%STATUS%% 1001829C", 19);
    CHECK(!st_license_ok(&p, ST_LIC_DATABASE) && p.status[ST_LIC_DATABASE] == 0x0001829Cu && !st_license_ok(&p, ST_LIC_LOADED),
          "a refused part, and one that never ran, are not ok");

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/licenses", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"loaded\":[{\"product\":\"BASIC\",\"producer\":\"VSI\",\"units\":\"0\"") &&
          strstr(body, "\"product\":\"FMS\"") && strstr(body, "\"per_core\":true") && strstr(body, "\"node\":\"X86VMS\"") &&
          strstr(body, "\"units_required\":\"2\""), "the loaded licences and the charge, to anyone");
    CHECK(strstr(body, "\"database\":[]") && strstr(body, "\"database\":{\"read\":false,\"vms_status\":\"%X0001829C\"") &&
          strstr(body, "\"loaded\":{\"read\":true}") && !strstr(body, "ISV-EXAMPLE"),
          "the database refused without privilege, with OpenVMS's status, and nothing of it shown");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/licenses", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && !strstr(body, "\"read\":false") &&
          strstr(body, "\"database\":[{\"product\":\"BASIC\",\"producer\":\"VSI\",\"issuer\":\"VSI\",\"authorization\":\"ISV-EXAMPLE-D000000000001\"") &&
          strstr(body, "\"file\":\"SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB;1\""), "with SYSPRV the database is read");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

typedef struct { int n[ST_PROD_PARTS]; st_product r[8]; int nr; } prod_got;
static int prod_keep(const st_product *r, void *ctx)
{
    prod_got *g = ctx;
    g->n[r->part]++;
    if (g->nr < 8) g->r[g->nr++] = *r;
    return 0;
}
static void prod_feed(st_product_parser *p, const char *const *lines)
{
    int i;
    for (i = 0; lines[i]; i++) st_product_line(p, lines[i], strlen(lines[i]));
    st_product_end(p);
}

static void test_products(void)
{
    /* PCSI's own layout (x86, 2026-10-16), shortened: the rule gives the columns. */
    static const char *const out[] = {
        "%%PART%% PRODUCTS",
        "------------------------------------ ----------- --------- ------------------------------------ ------------------------------------",
        "PRODUCT                              KIT TYPE    STATE     MAINTENANCE                          REFERENCED BY",
        "------------------------------------ ----------- --------- ------------------------------------ ------------------------------------",
        "EXAMPLE X86VMS LONGPRODUCTNAME V11.4-13E3 Full LP     Installed",
        "VSI X86VMS SSL3 V3.0-21              Full LP     Installed                                      EXAMPLE X86VMS WIDGET V1.2-3",
        "                                                                                                VSI X86VMS TCPIP V6.0-31",
        "VSI X86VMS VMS E9.2-3                Oper System Installed VSI X86VMS VMS923X_UPDATE V2.0",
        "------------------------------------ ----------- --------- ------------------------------------ ------------------------------------",
        "3 items found",
        "%%STATUS%% 00000001",
        "%%PART%% HISTORY",
        "------------------------------------ ----------- ----------- --- -------------------- --- ------------ -----------------------------",
        "PRODUCT                              KIT TYPE    OPERATION   VAL DATE AND TIME        ERR USER NAME    REMARK",
        "------------------------------------ ----------- ----------- --- -------------------- --- ------------ -----------------------------",
        "VSI X86VMS VMS923X_UPDATE V2.0       Patch       Install     Val 02-MAY-2026 14:40:11   0 SYSTEM       Patch for VMS E9.2-3",
        "EXAMPLE X86VMS WIDGET V1.2-2         Full LP     Remove       -  12-OCT-2026 10:15:02   0 SYSTEM",
        "------------------------------------ ----------- ----------- --- -------------------- --- ------------ -----------------------------",
        "2 items found                      Validation codes: Val=kit passed test,   (M)=manifest not found, (U)=unsigned kit,",
        "                                                       Sys=kit from OS media, (D)=disabled by user,   (C)=CDSA unavailable,",
        "VMSINSTAL history file SYS$COMMON:[SYSUPD]VMSINSTAL.HISTORY;1 contains additional information",
        "%%STATUS%% 00000001",
        NULL };
    static const char *const refused[] = { "%%PART%% PRODUCTS", "%PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege",
                                           "%%STATUS%% 1652800A", NULL };
    st_product_parser p;
    prod_got g;
    st_vmsinstal v;
    result b;
    hdr t[3], adm[3];
    char tc[100], tcsrf[65], ac[100], acsrf[65];
    const char *body;

    memset(&g, 0, sizeof g);
    st_product_init(&p, prod_keep, &g);
    prod_feed(&p, out);
    CHECK(g.n[ST_PROD_PRODUCTS] == 3 && g.n[ST_PROD_HISTORY] == 2, "every row of both tables, nothing of the count or legend");
    CHECK(!strcmp(g.r[0].producer, "EXAMPLE") && !strcmp(g.r[0].base, "X86VMS") && !strcmp(g.r[0].name, "LONGPRODUCTNAME") &&
          !strcmp(g.r[0].version, "V11.4-13E3") && !strcmp(g.r[0].kit_type, "Full LP") && !strcmp(g.r[0].state, "Installed"),
          "a product too long for its column: its four words, and the rest of the line shifted");
    CHECK(!strcmp(g.r[1].referenced_by, "EXAMPLE X86VMS WIDGET V1.2-3, VSI X86VMS TCPIP V6.0-31") && !g.r[1].maintenance[0],
          "an indented line continues REFERENCED BY");
    CHECK(!strcmp(g.r[2].kit_type, "Oper System") && !strcmp(g.r[2].maintenance, "VSI X86VMS VMS923X_UPDATE V2.0"),
          "a kit type that fills its column; maintenance");
    CHECK(g.r[3].part == ST_PROD_HISTORY && !strcmp(g.r[3].kit_type, "Patch") && !strcmp(g.r[3].operation, "Install") &&
          !strcmp(g.r[3].validation, "Val") && !strcmp(g.r[3].date, "02-MAY-2026 14:40:11") && !strcmp(g.r[3].error, "0") &&
          !strcmp(g.r[3].user, "SYSTEM") && !strcmp(g.r[3].remark, "Patch for VMS E9.2-3"), "a history row, every column");
    CHECK(!strcmp(g.r[4].operation, "Remove") && !strcmp(g.r[4].validation, "-") && !g.r[4].remark[0], "a removal");
    CHECK(st_product_ok(&p, ST_PROD_PRODUCTS) && st_product_ok(&p, ST_PROD_HISTORY), "each part's status");

    memset(&g, 0, sizeof g);
    st_product_init(&p, prod_keep, &g);
    prod_feed(&p, refused);
    CHECK(!st_product_ok(&p, ST_PROD_PRODUCTS) && p.status[ST_PROD_PRODUCTS] == 0x0652800Au && p.seen[ST_PROD_PRODUCTS] &&
          !st_product_ok(&p, ST_PROD_HISTORY) && !g.n[0] &&
          !strcmp(p.message[ST_PROD_PRODUCTS], "%PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege"),
          "refused without SYSLCK (PRIVCLASS1), with PRODUCT's own message, and a part that never ran");

    CHECK(st_vmsinstal_line("                         | VSIFMS           |  2.6    |  5-JUL-2024 | S     | S     | X86VMS | SYSTEM       | VSI         ", 121, &v) &&
          !v.name[0] && !strcmp(v.mnemonic, "VSIFMS") && !strcmp(v.version, "2.6") && !strcmp(v.date, "5-JUL-2024") &&
          !strcmp(v.status, "S") && !strcmp(v.ivp, "S") && !strcmp(v.node, "X86VMS") && !strcmp(v.installer, "SYSTEM") &&
          !strcmp(v.signature, "VSI"), "a VMSINSTAL run: nine fields, a one-digit day");
    CHECK(!st_vmsinstal_line("Name                     | Mnemonic         | Version | Date        | Status| IVP   | Node   | Installer    | VALSIGN     ", 121, &v) &&
          !st_vmsinstal_line("--------------------------------------------------------------------|---------------------------------------------------", 120, &v) &&
          !st_vmsinstal_line("VMSINSTAL Product Installation History File", 43, &v) &&
          !st_vmsinstal_line("a|b|c|21-APR-2023|e|f|g|h|i|j", 29, &v), "the header, a rule, a title and ten fields are not runs");

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/products", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"products\":[]") && strstr(body, "\"history\":[]") &&
          strstr(body, "\"products\":{\"read\":false,\"vms_status\":\"%X0652800A\",\"vms_message\":\"%PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege\"}"),
          "without SYSLCK: PCSI's refusal, by name, and nothing of it");
    CHECK(strstr(body, "\"vmsinstal\":[{\"name\":\"\",\"mnemonic\":\"EXAMPLEFMS\"") && strstr(body, "\"vmsinstal\":{\"read\":true}") &&
          strstr(body, "\"mnemonic\":\"EXAMPLEPAS\""), "VMSINSTAL's history to anyone, oldest first");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("GET", "/api/v1/products", adm, NULL, &b);
    CHECK(b.resp.status == 200 && !strstr(b.resp.body.data, "\"read\":false") && strstr(b.resp.body.data, "\"name\":\"WIDGET\""),
          "SYSLCK authorized, not switched on: read (PRODUCT switches it on itself, as on x86)");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"syslck\"]}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "SYSLCK"), "SYSLCK switched on (authorized, not default)");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/products", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && !strstr(body, "\"read\":false") &&
          strstr(body, "\"products\":[{\"producer\":\"EXAMPLE\",\"base\":\"X86VMS\",\"name\":\"WIDGET\",\"version\":\"V1.2-3\",\"kit_type\":\"Full LP\",\"state\":\"Installed\",\"maintenance\":[],\"referenced_by\":[]}"),
          "with SYSLCK the installed products");
    CHECK(strstr(body, "\"referenced_by\":[\"EXAMPLE X86VMS WIDGET V1.2-3\",\"VSI X86VMS TCPIP V6.0-31\"]") &&
          strstr(body, "\"name\":\"LONGPRODUCTNAME\""), "lists as arrays; the long name");
    CHECK(strstr(body, "\"history\":[{\"producer\":\"EXAMPLE\",\"base\":\"X86VMS\",\"name\":\"WIDGET\",\"version\":\"V1.2-3\",\"kit_type\":\"Full LP\",\"operation\":\"Install\",\"validation\":\"(U)\",\"date\":\"12-OCT-2026 10:15:02\"") &&
          strstr(body, "\"truncated\":false"), "and the history, newest first as PCSI gives it");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* Monitoring (Phase 13, D21): raw counters, and only the processes the viewer may see. */
static void test_monitor(void)
{
    result b;
    hdr t[3], adm[3];
    char tc[100], tcsrf[65], ac[100], acsrf[65];
    const char *body;
    long long first = 0;

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/monitor", t, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"cpus\":4") && strstr(body, "\"modes\":{\"interrupt\":0,\"mp_synch\":") &&
          strstr(body, "\"idle\":") && strstr(body, "\"processes\":58"), "the CPU modes, and every process on the system counted");
    CHECK(strstr(body, "\"states\":{\"CUR\":1,\"COM\":") && strstr(body, "\"FPG\":0}") &&
          strstr(body, "\"counters\":{\"page_faults\":") && strstr(body, "\"mailbox_writes\":"), "states and counters, by MONITOR's names");
    CHECK(strstr(body, "\"disks\":[{\"device\":\"DKA0:\",\"operations\":") && strstr(body, "\"memory\":{\"total\":8589934592"),
          "each disk's operations, the system disk first; memory");
    CHECK(strstr(body, "\"visible\":[{\"pid\":") && strstr(body, "\"username\":\"STEWARD_TEST\"") &&
          !strstr(body, "\"username\":\"WEBMASTER\"") && !strstr(body, "\"username\":\"SYSTEM\"") &&
          strstr(body, "\"truncated\":false"), "without WORLD, only your own processes");
    {
        const char *at = strstr(body, "\"sampled_at_ms\":");
        if (at) first = strtoll(at + 16, NULL, 10);   /* not atoll: VSI C did not declare it here (%CC-I-IMPLICITFUNC) */
    }
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"world\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"username\":\"SYSTEM\"") && strstr(body, "\"name\":\"OPCOM\""),
          "with WORLD, everyone's (WEBMASTER's was stopped by the Phase 8b test)");
    {
        const char *at = strstr(body, "\"sampled_at_ms\":");
        CHECK(at && first > 0 && strtoll(at + 16, NULL, 10) >= first, "each reading stamped, in order");
    }
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* The recording's records and ring (D22): encoded with explicit offsets, read back
   whole; slots by the nearest boundary; a plan that never reaches past the ring. */
static void test_mrec(void)
{
    static st_monitor m, back;
    static unsigned char rec[ST_MREC_SIZE];
    static st_mrec_point pts[400];
    st_mrec_header h, h2;
    unsigned int slot = 0, step = 0;
    long long day = 86400000LL, t0 = 1792000020000LL;   /* a whole minute */
    int n, i, ok;

    memset(&m, 0, sizeof m);
    m.sampled_at_ms = t0 + 37;
    m.cpus = 4;
    m.modes[ST_MON_INTERRUPT] = -126;   /* negative on the x86 VM */
    m.modes[ST_MON_IDLE] = 5000000000LL;
    m.states[ST_MON_FPG] = 3;
    m.processes = 105;
    m.mem_total = 8ull << 30;
    m.mem_free = 5ull << 30;
    m.mem_modified = 12345;
    m.counters[ST_MON_MBWRITES] = 4294967295u;
    m.ndisks = ST_MAX_DISKS;
    for (i = 0; i < ST_MAX_DISKS; i++) {
        snprintf(m.disks[i].device, sizeof m.disks[i].device, "$1$DGA%d:", 1000 + i);
        m.disks[i].operations = 7u * (unsigned int) i;
    }
    st_mrec_encode(&m, 1441, rec);
    CHECK(rec[0] == 0 && rec[1] == 0 && rec[2] == 5 && rec[3] == 0xA1 && !memcmp(rec + 4, "SMR1", 4),
          "a reading's key big-endian (RMS orders it as a number), then its mark");
    CHECK(rec[8] == (unsigned char) ((t0 + 37) & 0xFF) && rec[16] == 4 && rec[20] == 105,
          "the time, CPUs and processes little-endian at their offsets");
    CHECK(!st_mrec_decode(rec, ST_MREC_SIZE, &back, &slot) && slot == 1441 &&
          back.sampled_at_ms == t0 + 37 && back.modes[ST_MON_INTERRUPT] == -126 &&
          back.modes[ST_MON_IDLE] == 5000000000LL && back.states[ST_MON_FPG] == 3 &&
          back.mem_free == (5ull << 30) && back.mem_modified == 12345 &&
          back.counters[ST_MON_MBWRITES] == 4294967295u, "every figure read back");
    CHECK(back.ndisks == ST_MAX_DISKS && !strcmp(back.disks[31].device, "$1$DGA1031:") &&
          back.disks[31].operations == 217, "all 32 disks, names and counts");
    CHECK(st_mrec_decode(rec, ST_MREC_SIZE - 1, &back, &slot) == -1, "a record of another length refused");
    rec[195] = 40;   /* ndisks' top byte: far more than 32 */
    CHECK(st_mrec_decode(rec, ST_MREC_SIZE, &back, &slot) == -1, "a disk count past 32 refused");
    CHECK(st_mrec_decode_header(rec, ST_MREC_SIZE, &h2) == -1, "a reading is not a header");

    h.interval_secs = 60;
    h.slots = st_mrec_slots(60, 7);
    h.started_ms = t0 - 3 * day;
    h.updated_ms = t0;
    CHECK(h.slots == 10080 && st_mrec_slots(60, 366) == 527040 && st_mrec_slots(5, 366) == ST_MREC_MAX_SLOTS &&
          st_mrec_slots(3600, 0) == 1, "slots: a week at a minute is 10,080; bounded both ways");
    st_mrec_encode_header(&h, rec);
    CHECK(!st_mrec_decode_header(rec, ST_MREC_SIZE, &h2) && h2.interval_secs == 60 && h2.slots == 10080 &&
          h2.started_ms == h.started_ms && h2.updated_ms == t0 && rec[3] == 0 && !memcmp(rec + 4, "SMH1", 4),
          "the header under key 0, read back");
    CHECK(st_mrec_decode(rec, ST_MREC_SIZE, &back, &slot) == -1, "a header is not a reading");
    rec[8] = 0; rec[9] = 0;   /* interval 0 */
    CHECK(st_mrec_decode_header(rec, ST_MREC_SIZE, &h2) == -1, "a header with no interval refused");

    CHECK(st_mrec_nearest(t0 + 29999, 60) == t0 && st_mrec_nearest(t0 + 30000, 60) == t0 + 60000 &&
          st_mrec_nearest(t0 - 200, 60) == t0, "the nearest boundary, a little late or a little early");
    CHECK(st_mrec_slot(t0 - 200, 60, 10080) == st_mrec_slot(t0 + 900, 60, 10080) &&
          st_mrec_slot(t0, 60, 10080) != st_mrec_slot(t0 + 60000, 60, 10080), "a reading's slot by its boundary");
    CHECK(st_mrec_slot(t0, 60, 10080) == st_mrec_slot(t0 + 7 * day, 60, 10080) &&
          st_mrec_slot(t0, 60, 10080) >= 1 && st_mrec_slot(t0, 60, 10080) <= 10080, "a week later, the same slot: the ring");
    CHECK(st_mrec_matches(t0 + 400, t0, 60) && !st_mrec_matches(t0 + 400 - 7 * day, t0, 60) &&
          !st_mrec_matches(0, 0, 60), "a record from the last lap does not match");

    n = st_mrec_plan(t0 + 45000, 360, 300, &h, pts, 400, &step);
    CHECK(step == 120 && n == 180 && pts[n - 1].want_ms == t0 && pts[0].want_ms == t0 - 179 * 120000LL,
          "6 hours in 300 points: every second minute, the newest boundary last");
    for (ok = 1, i = 1; i < n; i++) ok &= pts[i].want_ms - pts[i - 1].want_ms == 120000 &&
        pts[i].slot == st_mrec_slot(pts[i].want_ms, 60, 10080);
    CHECK(ok, "evenly spaced, each with its slot");
    n = st_mrec_plan(t0, 30 * 1440, 300, &h, pts, 400, &step);
    CHECK(step == 2040 && pts[0].want_ms > t0 - 7 * day, "a month asked of a week's ring: only the week");
    for (ok = 1, i = 1; i < n; i++) ok &= pts[i].slot != pts[0].slot;
    CHECK(ok, "no slot fetched twice (none from the far side of the ring)");
    n = st_mrec_plan(t0, 10, 300, &h, pts, 400, &step);
    CHECK(step == 60 && n == 11, "a short range: every reading");
    CHECK(st_mrec_plan(t0, 360, 300, &h, pts, 50, &step) == 50 && pts[49].want_ms == t0 && pts[0].want_ms == t0 - 49 * 120000LL,
          "no more than room for, the newest kept");
    CHECK(st_mrec_plan(t0, 360, 1, &h, pts, 400, &step) == 0, "one point is no range");
}

/* GET api/v1/monitor/history on the stub's made-up week (five-minute readings, a gap
   28 to 30 hours ago). */
static void test_monitor_history(void)
{
    result b;
    hdr t[3];
    char tc[100], tcsrf[65];
    const char *body, *p;
    int n;

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/monitor/history?minutes=360&points=300", t, NULL, &b);
    body = b.resp.body.data;
    for (n = 0, p = body; (p = strstr(p, "\"sampled_at_ms\":")); p++) n++;
    CHECK(b.resp.status == 200 && strstr(body, "\"recording\":true,\"interval_secs\":300,\"kept_secs\":604800") &&
          strstr(body, "\"step_secs\":300"), "the recording: five minutes, a week; 6 hours at every reading");
    CHECK(n >= 71 && n <= 73 && !strstr(body, "\"visible\"") && strstr(body, "\"disks\":[{\"device\":\"DKA0:\""),
          "6 hours: some 72 readings, the counters without processes");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor/history?minutes=2880&points=288", t, NULL, &b);
    body = b.resp.body.data;
    for (n = 0, p = body; (p = strstr(p, "\"sampled_at_ms\":")); p++) n++;
    CHECK(b.resp.status == 200 && strstr(body, "\"step_secs\":600") && n >= 274 && n <= 277,
          "2 days at ten minutes: the two hours the recorder was stopped missing");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor/history", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"step_secs\":300"), "by default, 6 hours");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor/history?points=1", t, NULL, &b);
    CHECK(b.resp.status == 400, "a point is not a range");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor/history?minutes=x", t, NULL, &b);
    CHECK(b.resp.status == 400, "minutes a number");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/monitor/history", NULL, NULL, &b);
    CHECK(b.resp.status == 401, "signed in only");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* ELV's translation, CLUE's summary and OPCOM's log, from lines as x86 wrote them
   (the node renamed). */
typedef struct { st_elv_event ev[8]; st_elv_field f[24]; int nev, nf; } elv_got;
static int got_event(const st_elv_event *ev, void *ctx)
{ elv_got *g = ctx; if (g->nev < 8) g->ev[g->nev++] = *ev; return 0; }
static int got_field(const st_elv_field *f, void *ctx)
{ elv_got *g = ctx; if (g->nf < 24) g->f[g->nf++] = *f; return 0; }
static void elv_feed_all(st_elv_parser *p, const char *const *lines)
{ int i; for (i = 0; lines[i]; i++) st_elv_line(p, lines[i], strlen(lines[i])); }

typedef struct { st_opcom_msg m[8]; int n; } opcom_got;
static int got_opcom(const st_opcom_msg *m, void *ctx)
{ opcom_got *g = ctx; if (g->n < 8) g->m[g->n++] = *m; return 0; }

static void test_errlog_parsers(void)
{
    static const char *const list[] = {
        "%%PART%% EVENTS",
        "Output file DISK$X:[U]PE_ONE.LIS;1 created at 17-OCT-2026 09:44:52.97", "",
        "Output for SYS$SYSROOT:[SYSERR]ERRLOG.SYS;1", "",
        "EVENT  EVENT_TYPE_____________________________  TIMESTAMP______________  NODE__  EVENT_CLASS____________________________",
        "1      New File Created                         20-APR-2023 13:16:52.12  NODE1   CONTROL_ENTRIES                        ",
        "1801   Crash Restart                            13-OCT-2026 15:33:12.11  NODE1   BUGCHECKS                              ",
        "1807   Volume Mount                              7-OCT-2026 09:43:36.42  NODE1   VOLUME_CHANGES",
        "Number of events by event class:       ",
        "%%STATUS%% 00000001", NULL };
    static const char *const entry[] = {
        "%%PART%% ENTRY", "Output for SYS$SYSROOT:[SYSERR]ERRLOG.SYS;1", "",
        "EVENT  EVENT_TYPE_____________________________  TIMESTAMP______________  NODE__  EVENT_CLASS____________________________",
        "1769   System Service Message                   10-OCT-2026 14:07:35.24  NODE1   CONTROL_ENTRIES                        ", "",
        "DESCRIPTION__________________________________   RANGE___   VALUE_____________   TRANSLATED_VALUE_______________________",
        "   Hardware Architecture                                   5                    Intel X86                              ",
        "   DSR String                                              QEMU Standard PC (Q35 + ICH9, *",
        "",
        "   Processor Status                             <63:00>:   0x0000000000000000                                          ",
        "      Current Mode                              <04:03>:   0x0                  Kernel                                 ",
        "   Message                                                 ",
        "   CPU   0 LID: 0x00000000  Die: 0xFFFF Package:  0 Core:  0 Thread  0 ACPI:    0",
        "%%STATUS%% 00000001", NULL };
    static const char *const refused[] = {
        "%%PART%% EVENTS", "%ELV-E-FILOPNERR, error opening SYS$SYSROOT:[SYSERR]ERRLOG.SYS;1",
        "-RMS-E-FNF, file not found", "-RMS-E-FNF, file not found", "%%STATUS%% 00000001", NULL };
    static const char *const clue[] = {
        "OpenVMS Operating System, Version E9.2-4   -- System Dump Analysis   13-OCT-2026 15:17:29.80     Page     1",
        "Crashdump Summary Information:", "", "",
        "Crash Time:        13-OCT-2026 15:17:29.80",
        "Bugcheck Type:     PGFIPLHI, Pagefault with IPL too high",
        "Node:              NODE1  (Standalone)",
        "Current Process:   USB$UCM_SERVER",
        "Failing PC:        FFFF8300.06EB4930    SYS$HUBDRIVER+80001330   (HUBDRIVER + 00001330 / line 57539)",
        "Crash/Primary CPU: 0./0.",
        "EXE$GL_FLAGS:      init,fatal_bug,bugdump",
        "System Uptime:               0 00:00:26.19", "",
        "Stack Pointers:", "KSP = FFFFFFFF.8C04D860   ESP = 00000000.7FF8BE00", "Bugcheck Type:     NOT_THIS_ONE", NULL };
    static const char *const opcom[] = {
        "", "%%%%%%%%%%%  OPCOM  15-OCT-2026 16:05:50.50  %%%%%%%%%%%",
        "Operator status for operator NODE1::SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;243",
        "CENTRAL, PRINTER, TAPES,", "OPER11, OPER12", "",
        "%%%%%%%%%%%  OPCOM  15-OCT-2026 16:06:09.11  %%%%%%%%%%%", "Message from user IAIN on NODE1",
        "FTA1123_IAIN, Steward test: OPCOM check after restart", "",
        "%%%%%%%%%%%  OPCOM  15-OCT-2026 16:10:50.51  %%%%%%%%%%%", "Logfile time stamp", "",
        "%%%%%%%%%%%  OPCOM  16-OCT-2026 12:06:03.53  %%%%%%%%%%%", "Message from user SYSTEM on NODE1",
        "%TCPIP-F-LPD_BADPORT, error getting a port", "-SYSTEM-F-TIMEOUT, device timeout", NULL };
    static elv_got g;
    static st_elv_parser p;
    static st_clue_summary cs;
    static st_opcom_parser op;
    static opcom_got og;
    char iso[20];
    int i;

    memset(&g, 0, sizeof g);
    st_elv_init(&p, got_event, got_field, &g);
    elv_feed_all(&p, list);
    CHECK(g.nev == 3 && g.ev[0].number == 1 && !strcmp(g.ev[0].type, "New File Created") &&
          !strcmp(g.ev[0].node, "NODE1") && !strcmp(g.ev[0].cls, "CONTROL_ENTRIES"), "ELV one-line: each event's columns");
    CHECK(g.ev[1].number == 1801 && !strcmp(g.ev[1].type, "Crash Restart") && !strcmp(g.ev[1].iso, "2026-10-13T15:33:12") &&
          !strcmp(g.ev[1].when, "13-OCT-2026 15:33:12.11") && !strcmp(g.ev[1].cls, "BUGCHECKS"), "times as ELV gives them, and ISO");
    CHECK(!strcmp(g.ev[2].iso, "2026-10-07T09:43:36") && !strcmp(g.ev[2].cls, "VOLUME_CHANGES"),
          "a day of one digit; the last column without its padding");
    CHECK(p.status_seen && p.status == 1 && !st_elv_refused(&p) && g.nf == 0, "the part's status; no refusal; no fields in a list");

    memset(&g, 0, sizeof g);
    st_elv_init(&p, got_event, got_field, &g);
    elv_feed_all(&p, entry);
    CHECK(g.nev == 1 && g.ev[0].number == 1769 && g.nf == 6, "ELV entry: the event, then its fields");
    CHECK(!strcmp(g.f[0].description, "Hardware Architecture") && !strcmp(g.f[0].value, "5") &&
          !strcmp(g.f[0].translated, "Intel X86") && !g.f[0].indent && !g.f[0].text && !g.f[0].group,
          "a field: description, value, translation");
    CHECK(!strcmp(g.f[1].value, "QEMU Standard PC (Q35 + ICH9, *") && !g.f[1].translated[0],
          "a value longer than its column runs on, whole");
    CHECK(g.f[2].group && !strcmp(g.f[2].range, "<63:00>:") && !strcmp(g.f[2].value, "0x0000000000000000"),
          "after a blank line, a new group; a bit range");
    CHECK(g.f[3].indent == 1 && !strcmp(g.f[3].description, "Current Mode") && !strcmp(g.f[3].translated, "Kernel"),
          "a bit field under it, indented");
    CHECK(!strcmp(g.f[4].description, "Message") && g.f[5].text &&
          !strcmp(g.f[5].description, "CPU   0 LID: 0x00000000  Die: 0xFFFF Package:  0 Core:  0 Thread  0 ACPI:    0"),
          "a message's line across the columns: free text, whole");

    memset(&g, 0, sizeof g);
    st_elv_init(&p, got_event, got_field, &g);
    elv_feed_all(&p, refused);
    CHECK(st_elv_refused(&p) && p.status == 1 && g.nev == 0 &&
          !strcmp(p.message, "%ELV-E-FILOPNERR, error opening SYS$SYSROOT:[SYSERR]ERRLOG.SYS;1 / -RMS-E-FNF, file not found"),
          "ELV's refusal told by its message, although its status is success; its repeat kept once");

    st_vms_time_iso("13-OCT-2026 15:33:12.11", iso);
    CHECK(!strcmp(iso, "2026-10-13T15:33:12"), "VMS time to ISO");
    st_vms_time_iso("13-OCX-2026 15:33:12.11", iso);
    CHECK(!iso[0], "not a month: none");
    st_vms_time_iso("32-OCT-2026 15:33:12.11", iso);
    CHECK(!iso[0], "not a day: none");

    st_clue_init(&cs);
    for (i = 0; clue[i] && !cs.done; i++) st_clue_line(&cs, clue[i], strlen(clue[i]));
    CHECK(cs.done && !strcmp(st_clue_get(&cs, "Bugcheck Type"), "PGFIPLHI, Pagefault with IPL too high") &&
          !strcmp(st_clue_get(&cs, "Crash Time"), "13-OCT-2026 15:17:29.80") &&
          !strcmp(st_clue_get(&cs, "System Uptime"), "0 00:00:26.19"), "CLUE: the summary's values");
    CHECK(!strcmp(st_clue_get(&cs, "Crash/Primary CPU"), "0./0.") && !strcmp(st_clue_get(&cs, "EXE$GL_FLAGS"), "init,fatal_bug,bugdump") &&
          !strcmp(st_clue_get(&cs, "Failing PC"), "FFFF8300.06EB4930    SYS$HUBDRIVER+80001330   (HUBDRIVER + 00001330 / line 57539)"),
          "keys with slashes and dollars; a value with colons in it");
    CHECK(cs.nitems == 8 && !st_clue_get(&cs, "Crashdump Summary Information")[0] && !st_clue_get(&cs, "KSP = FFFFFFFF.8C04D860   ESP = 00000000.7FF8BE00")[0],
          "headings and the registers left out; nothing after Stack Pointers");
    CHECK(st_valid_clue_name("CLUE$X86VMS_131026_1517.LIS") && st_valid_clue_name("CLUE$NODE_1_010101_0000.LIS"),
          "CLUE listing names");
    CHECK(!st_valid_clue_name("clue$x86vms_131026_1517.lis") && !st_valid_clue_name("CLUE$X86VMS_131026_1517.LIS;1") &&
          !st_valid_clue_name("CLUE$[-]X_131026_1517.LIS") && !st_valid_clue_name("CLUE$X86VMS_13102_1517.LIS") &&
          !st_valid_clue_name("CLUE$HISTORY.DAT") && !st_valid_clue_name("SYSUAF.DAT"),
          "nothing else: no version, path, lower case or other file");

    memset(&og, 0, sizeof og);
    st_opcom_init(&op, got_opcom, &og);
    for (i = 0; opcom[i]; i++) st_opcom_line(&op, opcom[i], strlen(opcom[i]));
    CHECK(og.n == 3, "OPCOM: a message is emitted when the next begins");
    st_opcom_end(&op);
    CHECK(og.n == 4, "and the last at the end");
    CHECK(!strcmp(og.m[0].iso, "2026-10-15T16:05:50") && !og.m[0].from[0] &&
          !strcmp(og.m[0].text, "Operator status for operator NODE1::SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;243\nCENTRAL, PRINTER, TAPES,\nOPER11, OPER12"),
          "a message of several lines, not from a user");
    CHECK(!strcmp(og.m[1].from, "IAIN") && !strcmp(og.m[1].node, "NODE1") &&
          !strcmp(og.m[1].text, "FTA1123_IAIN, Steward test: OPCOM check after restart") && !og.m[1].stamp,
          "from a user, on a node, with its text");
    CHECK(og.m[2].stamp && !og.m[3].stamp && !strcmp(og.m[3].text, "%TCPIP-F-LPD_BADPORT, error getting a port\n-SYSTEM-F-TIMEOUT, device timeout"),
          "the hourly time stamp marked; a message's own % lines are its text");
}

/* The error log's endpoints on the stub: refused without SYSPRV, as on x86. */
static void test_errlog_api(void)
{
    result b;
    hdr t[3], adm[3];
    char tc[100], tcsrf[65], ac[100], acsrf[65];
    const char *body, *q;
    int n;

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/errorlog", t, NULL, &b);
    CHECK(b.resp.status == 403 && strstr(b.resp.body.data, "%ELV-E-FILOPNERR") &&
          strstr(b.resp.body.data, "-RMS-E-PRV, insufficient privilege"), "without SYSPRV, the error log refused with ELV's words: PRV");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes", t, NULL, &b);
    CHECK(b.resp.status == 403, "the crash listings refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/operator-log", t, NULL, &b);
    CHECK(b.resp.status == 403, "OPCOM's log refused");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/device-errors", t, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"devices\":[{\"device\":\"DKA100:\",\"errors\":2}],\"scanned\":3}"),
          "device error counts: anyone's");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("GET", "/api/v1/errorlog", adm, NULL, &b);
    CHECK(b.resp.status == 403, "SYSPRV authorized but not switched on: refused (D9)");
    st_resp_free(&b.resp);
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog", adm, NULL, &b);
    body = b.resp.body.data;
    for (n = 0, q = body; (q = strstr(q, "\"number\":")); q++) n++;
    CHECK(b.resp.status == 200 && strstr(body, "{\"days\":30,\"file\":\"ERRLOG.SYS\",\"events\":[{\"number\":1005,\"type\":\"Volume Dismount\",\"time\":\"") &&
          n == 6 && strstr(body, "\"node\":\"STUB01\",\"class\":\"BUGCHECKS\"") && strstr(body, "\"truncated\":false"),
          "with SYSPRV: the last 30 days, oldest first");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog?days=0", adm, NULL, &b);
    for (n = 0, q = b.resp.body.data; (q = strstr(q, "\"number\":")); q++) n++;
    CHECK(b.resp.status == 200 && n == 11, "days=0: the whole file");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog?days=x", adm, NULL, &b);
    CHECK(b.resp.status == 400, "days a number");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/1008", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "\"event\":{\"number\":1008,\"type\":\"Crash Restart\"") &&
          strstr(body, "{\"description\":\"Hardware Architecture\",\"value\":\"5\",\"translated\":\"Intel X86\"}") &&
          strstr(body, "{\"description\":\"Current Mode\",\"range\":\"\\u003c04:03\\u003e:\",\"value\":\"0x0\",\"translated\":\"Kernel\",\"indent\":1}") &&
          strstr(body, "\"group\":true"), "one event, field by field");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/1006", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"text\":\"CPU   0 LID:"), "a message's line as text");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/99999", adm, NULL, &b);
    CHECK(b.resp.status == 404, "no such event: 404");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/1;2", adm, NULL, &b);
    CHECK(b.resp.status == 400, "an event number is digits only");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "{\"name\":\"CLUE$STUB01_130926_1517.LIS\",\"time\":\"2026-09-13T15:17:29\",\"bugcheck\":\"PGFIPLHI, Pagefault with IPL too high\",\"process\":\"USB$UCM_SERVER\"") &&
          strstr(body, "\"bugcheck\":\"INCONSTATE, Inconsistent I/O data base\""), "the crashes, each with its summary");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes/CLUE$STUB01_130926_1517.LIS", adm, NULL, &b);
    body = b.resp.body.data;
    CHECK(b.resp.status == 200 && strstr(body, "{\"key\":\"Module\",\"value\":\"SYS$HUBDRIVER    (Link Date/Time: 27-JUL-2026 11:28:12.75)\"}") &&
          strstr(body, "\"text\":\"OpenVMS Operating System") && strstr(body, "Stack Pointers:\\nKSP = "), "one listing: summary and text");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes/SYSUAF.DAT", adm, NULL, &b);
    CHECK(b.resp.status == 400, "only CLUE listings by name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes/CLUE$STUB01_010101_0000.LIS", adm, NULL, &b);
    CHECK(b.resp.status == 404, "a listing that is not there: 404");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/operator-log", adm, NULL, &b);
    body = b.resp.body.data;
    for (n = 0, q = body; (q = strstr(q, "\"time\":")); q++) n++;
    CHECK(b.resp.status == 200 && n == 4 && strstr(body, "\"file\":\"SYS$SYSROOT:[SYSMGR]OPERATOR.LOG;12\",\"messages\":[{\"time\":\"2026-10-17T08:00:01\",\"from\":\"SYSTEM\"") &&
          !strstr(body, "time stamp"), "OPCOM's log: newest first, the time stamps left out");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/operator-log?stamps=1", adm, NULL, &b);
    for (n = 0, q = b.resp.body.data; (q = strstr(q, "\"time\":")); q++) n++;
    CHECK(b.resp.status == 200 && n == 6 && strstr(b.resp.body.data, "\"stamp\":true"), "with stamps=1, those too");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
}

/* 14b's changes on the stub (D24): renaming the error log, reading a renamed one,
   deleting crash listings. They change the stub's state, so they run last. */
static void test_errlog_changes(void)
{
    result b;
    hdr t[3], adm[3];
    char tc[100], tcsrf[65], ac[100], acsrf[65], name[32];
    const char *body, *q;

    CHECK(st_valid_errlog_name("ERRLOG.SYS") && st_valid_errlog_name("ERRLOG_20261017_1130.SYS") &&
          !st_valid_errlog_name("ERRLOG.OLD") && !st_valid_errlog_name("ERRLOG_2026101_11300.SYS") &&
          !st_valid_errlog_name("errlog.sys") && !st_valid_errlog_name("ERRLOG_20261017_1130.SYS;1") &&
          !st_valid_errlog_name("[-]ERRLOG.SYS"), "error log names: ERRLOG.SYS and renamed ones only");
    st_errlog_renamed(2026, 3, 7, 9, 5, name);
    CHECK(!strcmp(name, "ERRLOG_20260307_0905.SYS") && st_valid_errlog_name(name), "a renamed log's name");

    sign_in("{\"username\":\"steward_test\",\"password\":\"test-pass\"}", tc, sizeof tc, tcsrf);
    t[0].n = "HTTP_COOKIE"; t[0].v = tc; t[1].n = "HTTP_X_STEWARD_CSRF"; t[1].v = tcsrf; t[2].n = NULL;
    call("GET", "/api/v1/errorlog/files", t, NULL, &b);
    CHECK(b.resp.status == 403, "the files: refused without SYSPRV");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/errorlog/new", t, "{}", &b);
    CHECK(b.resp.status == 403, "a new error log: refused without SYSPRV");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/crashes/CLUE$STUB01_130926_1517.LIS", t, NULL, &b);
    CHECK(b.resp.status == 403, "deleting a listing: refused without SYSPRV");
    st_resp_free(&b.resp);

    sign_in("{\"username\":\"steward_adm\",\"password\":\"admin-pass\"}", ac, sizeof ac, acsrf);
    adm[0].n = "HTTP_COOKIE"; adm[0].v = ac; adm[1].n = "HTTP_X_STEWARD_CSRF"; adm[1].v = acsrf; adm[2].n = NULL;
    call("PUT", "/api/v1/session/privileges", adm, "{\"enabled\":[\"sysprv\"]}", &b);
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/files", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"files\":[{\"name\":\"ERRLOG.SYS\",\"blocks\":1440,\"created\":\"2023-04-20T13:16:52\"},{\"name\":\"ERRLOG_20260101_0900.SYS\""),
          "with SYSPRV: ERRLOG.SYS and the one renamed earlier");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog?days=0&file=ERRLOG_20260101_0900.SYS", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"file\":\"ERRLOG_20260101_0900.SYS\",\"events\":[{\"number\":1000"),
          "a renamed log read by name");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog?file=SYSUAF.DAT", adm, NULL, &b);
    CHECK(b.resp.status == 400, "no other file by name");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/errorlog/new", adm, "{}", &b);
    body = b.resp.body.data;
    q = strstr(body, "\"renamed_to\":\"");
    CHECK(b.resp.status == 200 && q && st_valid_errlog_name(strncpy(name, q + 14, 24)) && !(name[24] = '\0'),
          "a new error log: ERRLOG.SYS renamed, the new name returned");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog", adm, NULL, &b);
    CHECK(b.resp.status == 404 && strstr(b.resp.body.data, "ERRFMT creates it at its next record"),
          "until ERRFMT's next record there is no ERRLOG.SYS, and the viewer is told why");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/errorlog/new", adm, "{}", &b);
    CHECK(b.resp.status == 404, "and no new log of a log not there");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/errorlog/files", adm, NULL, &b);
    CHECK(b.resp.status == 200 && !strstr(b.resp.body.data, "\"ERRLOG.SYS\"") && strstr(b.resp.body.data, name),
          "the renamed log listed, readable");
    st_resp_free(&b.resp);

    call("DELETE", "/api/v1/crashes/SYSUAF.DAT", adm, NULL, &b);
    CHECK(b.resp.status == 400, "only CLUE listings deleted by name");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/crashes/purge", adm, "{\"before\":\"2026-13-01\"}", &b);
    CHECK(b.resp.status == 422, "purge: before a real day");
    st_resp_free(&b.resp);
    call("POST", "/api/v1/crashes/purge", adm, "{\"before\":\"2026-05-01\"}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"before\":\"2026-05-01\",\"deleted\":[\"CLUE$STUB01_020426_0310.LIS\"],\"failed\":0}"),
          "purge before 1 May 2026: April's crash only");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/crashes/CLUE$STUB01_130926_1517.LIS", adm, NULL, &b);
    CHECK(b.resp.status == 204, "one listing deleted");
    st_resp_free(&b.resp);
    call("GET", "/api/v1/crashes", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"crashes\":[]}"), "and none left");
    st_resp_free(&b.resp);
    call("DELETE", "/api/v1/crashes/CLUE$STUB01_130926_1517.LIS", adm, NULL, &b);
    CHECK(b.resp.status == 404, "a listing already gone: 404");
    st_resp_free(&b.resp);
    CHECK(!st_plat_persona_active(), "no persona left active");
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
    cfg.gateway_secret = "";
    st_app_init(&cfg);

    test_fcgi();
    test_json();
    test_http();
    test_proxy();
    test_dispatch();
    test_privileges();
    test_filters();
    test_users();
    test_edit();
    test_system();
    test_access();
    test_lnm_parser();
    test_logicals();
    test_lnm_def();
    test_logical_changes();
    test_processes();
    test_process_stop();
    test_queues();
    test_queue_changes();
    test_sysgen();
    test_licenses();
    test_products();
    test_monitor();
    test_mrec();
    test_monitor_history();
    test_errlog_parsers();
    test_errlog_api();
    test_errlog_changes();
    test_create();
    test_gateway();
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
