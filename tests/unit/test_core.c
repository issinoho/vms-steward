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
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "{\"users\":[{\"username\":\"DISABLED\"") &&
          strstr(b.resp.body.data, "\"next\":null"),
          "with SYSPRV on, users list in SYSUAF (alphabetical) order");
    CHECK(strstr(b.resp.body.data, "\"flags\":[\"DISUSER\"]") != NULL, "flags are named as AUTHORIZE names them");
    st_resp_free(&b.resp);

    call("GET", "/api/v1/users?limit=2", adm, NULL, &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"next\":\"EXPIRED\""), "a page ends with a cursor");
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
         "{\"owner\":\"Steward test (stub)\",\"flags\":[],\"quotas\":{\"prio\":4},"
         "\"secondary_days\":[\"SAT\",\"SUN\"],\"restricted_hours\":{\"batch\":{\"primary\":[]}},"
         "\"authorized_privileges\":[\"TMPMBX\",\"NETMBX\"],\"password\":{\"lifetime_days\":90}}", &b);
    CHECK(b.resp.status == 200 && strstr(b.resp.body.data, "\"owner\":\"Steward test (stub)\""), "and it can be put back");
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
    test_gateway();
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
