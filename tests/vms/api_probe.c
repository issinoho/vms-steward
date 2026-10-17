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

   API_PROBE_SERVICE_ACCOUNT=<username> makes that account's processes count as
   Steward's own (refused by a stop, D16), so a test can check the refusal on a
   process of its own rather than on the real pool. API_PROBE_SERVICE_IMAGE=<image>
   does the same for Steward's image (a pool worker busy with a request), and
   API_PROBE_MAX_SYS_GROUP=<octal> for MAXSYSGROUP (system processes refused).

   With API_PROBE_SOAK=<n> defined, <path> is ignored and every read-only endpoint is
   requested n times over (Phase 5 load run on the node, without lighttpd): it prints
   the statuses, the process's page-file use and open-file quota after the first
   round and at the end, and stops at once if a persona is left active.

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
#include <starlet.h>
#include <jpidef.h>

void st_plat_vms_test_helper(const char *path);   /* st_plat_vms.c, tests only */
void st_plat_vms_test_svc_acct(const char *name);
void st_plat_vms_test_svc_img(const char *image);
void st_plat_vms_test_svc_grp(unsigned int group);
void st_plat_vms_test_sysgen(const char *path);
void st_plat_vms_test_license(const char *path);
void st_plat_vms_test_product(const char *path);
void st_plat_vms_test_errlog(const char *path);

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

/* One request through the dispatcher; prints it if print. Returns the status. */
static int one(const char *method, const char *path, const char *body, const char *if_match,
               const char *cookie, const char *csrf_hex, int print)
{
    st_buf p;
    st_request r;
    st_response resp;
    char m[8], uri[1024];
    const char *q;
    size_t k;
    int status;

    st_copy(uri, sizeof uri, path);
    q = strchr(uri, '?');
    st_buf_init(&p, 0);
    for (k = 0; method[k] && k < sizeof m - 1; k++)   /* the C RTL lowercases argv */
        m[k] = (char) ((method[k] >= 'a' && method[k] <= 'z') ? method[k] - 32 : method[k]);
    m[k] = '\0';
    nv(&p, "REQUEST_METHOD", m);
    nv(&p, "HTTP_X_STEWARD_CSRF", csrf_hex);
    if (if_match) nv(&p, "HTTP_IF_MATCH", if_match);
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
        st_buf_free(&p);
        return 0;
    }
    st_resp_init(&resp);
    st_app_handle(&r, 0, &resp);
    status = resp.status;
    if (print) {
        const char *et = strstr(st_buf_cstr(&resp.headers), "ETag: ");
        printf("%d %s%.*s%s\n", resp.status, et ? "ETag=" : "", et ? (int) strcspn(et + 6, "\r\n") : 0,
               et ? et + 6 : "", et ? " " : "");
        printf("%s\n", st_buf_cstr(&resp.body));
    }
    st_resp_free(&resp);
    st_request_free(&r);
    st_buf_free(&p);
    return status;
}

/* Page-file pages in use, and open files still allowed: a leak shows in one or both. */
static void usage(unsigned int *pagefile, unsigned int *files)
{
    unsigned int iosb[2], pgflquota = 0, pagfilcnt = 0;
    struct { unsigned short len, code; void *buf; unsigned short *ret; } it[4];
    it[0].len = 4; it[0].code = JPI$_PGFLQUOTA; it[0].buf = &pgflquota; it[0].ret = 0;
    it[1].len = 4; it[1].code = JPI$_PAGFILCNT; it[1].buf = &pagfilcnt; it[1].ret = 0;
    it[2].len = 4; it[2].code = JPI$_FILCNT; it[2].buf = files; it[2].ret = 0;
    memset(&it[3], 0, sizeof it[3]);
    *files = 0;
    sys$getjpiw(0, 0, 0, it, iosb, 0, 0);
    *pagefile = pgflquota - pagfilcnt;
}

static int soak(int rounds, const char *user, const char *cookie, const char *csrf_hex)
{
    static const char *const paths[] = {
        "/api/v1/session", "/api/v1/system", "/api/v1/users?limit=50", "/api/v1/users/@",
        "/api/v1/users/@/identifiers", "/api/v1/identifiers?type=all&limit=50",
        "/api/v1/identifiers/STEWARD_PROBE/holders", "/api/v1/access?limit=200",
        "/api/v1/users/NO_SUCH_USER_X", "/api/v1/uic/next?group=362",
    };
    unsigned int pf0 = 0, fc0 = 0, pf1, fc1;
    unsigned long counts[600];
    int i, j, n = 0;
    memset(counts, 0, sizeof counts);
    for (i = 0; i < rounds; i++) {
        for (j = 0; j < (int) (sizeof paths / sizeof paths[0]); j++) {
            char path[128];
            int st;
            const char *at = strchr(paths[j], '@');   /* @: the user; no format from a table */
            if (at) snprintf(path, sizeof path, "%.*s%s%s", (int) (at - paths[j]), paths[j], user, at + 1);
            else st_copy(path, sizeof path, paths[j]);
            st = one("GET", path, NULL, NULL, cookie, csrf_hex, 0);
            counts[st >= 0 && st < 600 ? st : 0]++;
            n++;
            if (st_plat_persona_active()) {
                printf("FAIL persona left active after %s (round %d)\n", path, i + 1);
                return 2;
            }
        }
        if (i == 0) usage(&pf0, &fc0);
    }
    usage(&pf1, &fc1);
    printf("%d requests:", n);
    for (i = 0; i < 600; i++) if (counts[i]) printf(" %d=%lu", i, counts[i]);
    printf("\npage file in use: %u after round 1, %u at the end (pagelets)\n", pf0, pf1);
    printf("open files left: %u after round 1, %u at the end\n", fc0, fc1);
    return counts[0] || counts[500] || fc1 < fc0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    st_plat_config pc;
    st_app_config cfg;
    st_session s;
    st_err e;
    unsigned char token[32];
    char hex[65], cookie[100], user[13];

    const char *method = argc > 4 ? argv[4] : "GET";
    const char *body = (argc > 5 && strcmp(argv[5], "-")) ? argv[5] : NULL;
    char csrf_hex[65];

    if (argc < 4 || argc > 7 || !st_valid_username(argv[1], user)) {
        fprintf(stderr, "usage: api_probe <username> <privileges|-> <path> [<method> [<body>|- [<if-match>]]]\n");
        return 1;
    }
    memset(&pc, 0, sizeof pc);
    pc.session_file = "[.build]probe_sessions.dat";
    /* An audit log to append to and read back (access history): a scratch copy,
       never the service's own. Unset, records go to stderr. */
    pc.audit_file = getenv("API_PROBE_AUDIT") ? getenv("API_PROBE_AUDIT") : "";
    /* A recording (D22) to read: one written by a test recorder, never the pool's. */
    pc.history_file = getenv("API_PROBE_MONITOR_FILE") ? getenv("API_PROBE_MONITOR_FILE") : "";
    if (st_plat_init(&pc, &e)) { fprintf(stderr, "init: %s\n", e.text); return 1; }
    /* A D14 helper procedure to test in place of the installed one. */
    if (getenv("API_PROBE_LNM_HELPER")) st_plat_vms_test_helper(getenv("API_PROBE_LNM_HELPER"));
    if (getenv("API_PROBE_SYSGEN_HELPER")) st_plat_vms_test_sysgen(getenv("API_PROBE_SYSGEN_HELPER"));
    if (getenv("API_PROBE_LICENSE_HELPER")) st_plat_vms_test_license(getenv("API_PROBE_LICENSE_HELPER"));
    if (getenv("API_PROBE_PRODUCT_HELPER")) st_plat_vms_test_product(getenv("API_PROBE_PRODUCT_HELPER"));
    if (getenv("API_PROBE_ERRLOG_HELPER")) st_plat_vms_test_errlog(getenv("API_PROBE_ERRLOG_HELPER"));
    /* The account whose processes count as Steward's own (D16): by default this
       process's, the work account's, never the real pool's. */
    if (getenv("API_PROBE_SERVICE_ACCOUNT")) st_plat_vms_test_svc_acct(getenv("API_PROBE_SERVICE_ACCOUNT"));
    if (getenv("API_PROBE_SERVICE_IMAGE")) st_plat_vms_test_svc_img(getenv("API_PROBE_SERVICE_IMAGE"));
    if (getenv("API_PROBE_MAX_SYS_GROUP")) st_plat_vms_test_svc_grp((unsigned int) strtoul(getenv("API_PROBE_MAX_SYS_GROUP"), 0, 8));
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

    st_hex(s.csrf, sizeof s.csrf, csrf_hex);
    if (getenv("API_PROBE_SOAK")) {
        int rc = soak(atoi(getenv("API_PROBE_SOAK")), user, cookie, csrf_hex);
        st_plat_session_delete(s.key, &e);
        return rc ? 2 : 0;
    }
    one(method, argv[3], body, argc > 6 ? argv[6] : NULL, cookie, csrf_hex, 1);
    st_plat_session_delete(s.key, &e);
    return st_plat_persona_active() ? 2 : 0;
}
