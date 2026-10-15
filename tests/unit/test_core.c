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
    test_create();
    test_gateway();
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
