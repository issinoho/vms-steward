/* api_probe.c - one API request through the real dispatcher and the OpenVMS
   platform, as a named user, without that user's password. For checking Phase 2+
   results against AUTHORIZE on a test node.

   Usage: api_probe <username> <privileges|-> <path> [<method> [<body>|- [<if-match>]]]
     privileges: comma-separated names to switch on for the session (D9), or -
     e.g.  api_probe STEWARD_TEST - /api/v1/users/STEWARD_TEST
           api_probe STEWARD_TEST GRPPRV /api/v1/users
           api_probe IAIN SYSPRV /api/v1/users/STEWARD_TEST PATCH "{""owner"":""x""}" "<etag>"
   A body, if any, is sent as JSON with the session's CSRF token. The ETag is printed
   after the status when the response has one.

   It plants a session for <username> in a scratch store ([.BUILD]PROBE_SESSIONS.DAT),
   so the request runs under that user's persona exactly as a signed-in request does.
   Creating the persona needs IMPERSONATE and SYSPRV, so this runs from a privileged
   work account, never from the service. Test tool only: it is not built into the
   kit, and it reads, never writes, SYSUAF and RIGHTSLIST. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "st_app.h"
#include "svc.h"

static void nv(st_buf *b, const char *n, const char *v)
{
    size_t ln = strlen(n), lv = strlen(v);
    size_t l[2];
    int i;
    l[0] = ln; l[1] = lv;
    for (i = 0; i < 2; i++) {
        if (l[i] < 128) st_buf_putc(b, (char) l[i]);
        else {
            st_buf_putc(b, (char) (0x80 | ((l[i] >> 24) & 0x7F)));
            st_buf_putc(b, (char) ((l[i] >> 16) & 0xFF));
            st_buf_putc(b, (char) ((l[i] >> 8) & 0xFF));
            st_buf_putc(b, (char) (l[i] & 0xFF));
        }
    }
    st_buf_append(b, n, ln);
    st_buf_append(b, v, lv);
}

int main(int argc, char **argv)
{
    st_plat_config pc;
    st_app_config cfg;
    st_session s;
    st_err e;
    st_buf p;
    st_request r;
    st_response resp;
    unsigned char token[32];
    char hex[65], cookie[100], user[13], uri[1024];
    const char *q;

    const char *method = argc > 4 ? argv[4] : "GET";
    const char *body = (argc > 5 && strcmp(argv[5], "-")) ? argv[5] : NULL;
    char m[8], csrf_hex[65];
    size_t k;

    if (argc < 4 || argc > 7 || !st_valid_username(argv[1], user)) {
        fprintf(stderr, "usage: api_probe <username> <privileges|-> <path> [<method> [<body>|- [<if-match>]]]\n");
        return 1;
    }
    memset(&pc, 0, sizeof pc);
    pc.session_file = "[.build]probe_sessions.dat";
    pc.audit_file = "";
    if (st_plat_init(&pc, &e)) { fprintf(stderr, "init: %s\n", e.text); return 1; }
    memset(&cfg, 0, sizeof cfg);
    cfg.idle_secs = 900;
    cfg.absolute_secs = 3600;
    cfg.cookie_secure = 1;
    cfg.trusted_proxies = "";
    cfg.gateway_secret = "";
    st_app_init(&cfg);

    memset(&s, 0, sizeof s);
    st_plat_random(token, sizeof token);
    st_plat_random(s.csrf, sizeof s.csrf);
    st_plat_sha256(token, sizeof token, s.key);
    st_copy(s.username, sizeof s.username, user);
    s.created = s.last_seen = st_plat_time();
    st_copy(s.client, sizeof s.client, "127.0.0.1");
    if (strcmp(argv[2], "-")) {
        char list[256], *tok;
        st_copy(list, sizeof list, argv[2]);
        for (tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
            int bit;
            char *c;
            for (c = tok; *c; c++) if (*c >= 'a' && *c <= 'z') *c = (char) (*c - 'a' + 'A');   /* the C RTL lowercases argv */
            for (bit = 0; svc_priv_name(bit); bit++)
                if (!strcmp(svc_priv_name(bit), tok)) s.priv_enable[bit / 32] |= 1u << (bit % 32);
        }
    }
    if (st_plat_session_put(&s, &e)) { fprintf(stderr, "session: %s\n", e.text); return 1; }
    st_hex(token, sizeof token, hex);
    snprintf(cookie, sizeof cookie, "%s=%s", ST_COOKIE, hex);

    st_copy(uri, sizeof uri, argv[3]);
    q = strchr(uri, '?');
    st_buf_init(&p, 0);
    for (k = 0; method[k] && k < sizeof m - 1; k++)   /* the C RTL lowercases argv */
        m[k] = (char) ((method[k] >= 'a' && method[k] <= 'z') ? method[k] - 32 : method[k]);
    m[k] = '\0';
    st_hex(s.csrf, sizeof s.csrf, csrf_hex);
    nv(&p, "REQUEST_METHOD", m);
    nv(&p, "HTTP_X_STEWARD_CSRF", csrf_hex);
    if (argc > 6) nv(&p, "HTTP_IF_MATCH", argv[6]);
    if (body) {
        char len[16];
        snprintf(len, sizeof len, "%u", (unsigned) strlen(body));
        nv(&p, "CONTENT_TYPE", "application/json");
        nv(&p, "CONTENT_LENGTH", len);
    }
    nv(&p, "REQUEST_URI", uri);
    nv(&p, "QUERY_STRING", q ? q + 1 : "");
    nv(&p, "REMOTE_ADDR", "127.0.0.1");
    nv(&p, "HTTP_HOST", "probe");
    nv(&p, "HTTP_COOKIE", cookie);
    if (st_request_init(&r, (unsigned char *) p.data, p.len, body, body ? strlen(body) : 0)) {
        fprintf(stderr, "bad request\n");
        return 1;
    }
    st_resp_init(&resp);
    st_app_handle(&r, 0, &resp);
    {
        const char *et = strstr(st_buf_cstr(&resp.headers), "ETag: ");
        printf("%d %s%.*s%s\n", resp.status, et ? "ETag=" : "", et ? (int) strcspn(et + 6, "\r\n") : 0,
               et ? et + 6 : "", et ? " " : "");
        printf("%s\n", st_buf_cstr(&resp.body));
    }
    st_plat_session_delete(s.key, &e);
    st_resp_free(&resp);
    st_request_free(&r);
    st_buf_free(&p);
    return st_plat_persona_active() ? 2 : 0;
}
