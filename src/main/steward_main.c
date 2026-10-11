/* steward_main.c - the FastCGI server: one process, one connection, one request at a
   time, as a member of the pool lighttpd talks to (D1).

   Usage: steward -b 127.0.0.1:<port>      serve
          steward -v                       print the version
          steward -g                       print a new random gateway secret (64 hex
                                           characters, from OpenSSL's generator), for
                                           STEWARD$CONFIGURE

   Settings come from the environment (on OpenVMS getenv() also translates logical
   names, so STEWARD_POOL.COM defines them as process logicals):
     STEWARD_IDLE_SECS        idle session timeout            (default 900)
     STEWARD_ABSOLUTE_SECS    longest session                 (default 28800)
     STEWARD_TRUSTED_PROXIES  reverse proxies to believe (D7)  (default none)
     STEWARD_INSECURE_COOKIE  "1": no Secure flag, for the plain-HTTP dev server only
     STEWARD_AUDIT_FILE       audit log                       (default: stderr)
     STEWARD_SESSION_FILE     shared session store (OpenVMS)
     STEWARD_GATEWAY_SECRET   shared with lighttpd (vms/steward.conf), at least 32
                              characters. Unset: not enforced, with a warning.

   Only loopback peers are served: lighttpd runs on the same machine, and nothing else
   should reach the FastCGI port even if a firewall slips. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "st_fcgi.h"
#include "st_version.h"
#include "st_http.h"
#include "st_app.h"

#define PARAMS_LIMIT (64 * 1024)
#define BODY_LIMIT   (256 * 1024)
#define READ_TIMEOUT 30

static long env_long(const char *name, long dflt)
{
    const char *v = getenv(name);
    char *end;
    long n;
    if (!v || !*v) return dflt;
    n = strtol(v, &end, 10);
    return (*end || n <= 0) ? dflt : n;
}

static const char *env_str(const char *name)
{
    const char *v = getenv(name);
    return v ? v : "";
}

static int send_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        int k = (int) send(fd, p, n > 65536 ? 65536 : n, 0);
        if (k <= 0) { if (k < 0 && errno == EINTR) continue; return -1; }
        p += k;
        n -= (size_t) k;
    }
    return 0;
}

/* One request is ready: answer it into out. */
static void serve(st_fcgi_conn *conn, st_buf *out)
{
    st_request req;
    st_response resp;
    st_buf cgi;

    memset(&req, 0, sizeof req);   /* freed below even if never initialised */
    st_resp_init(&resp);
    st_buf_init(&cgi, 0);
    if (!st_buf_ok(&conn->params) ||
        st_request_init(&req, (const unsigned char *) conn->params.data, conn->params.len,
                        conn->body.data, conn->body.len) || req.too_many_params) {
        st_resp_problem(&resp, 400, "bad-request", "Malformed request", NULL, 0, NULL);
    } else {
        st_app_handle(&req, !st_buf_ok(&conn->body), &resp);
    }
    st_request_free(&req);

    if (!st_plat_privileges_clean()) {
        /* SYSPRV is for $PERSONA_CREATE alone (D2); still on means a path skipped
           turning it off. Stop rather than serve anything with it. */
        st_plat_log("SYSPRV still enabled after a request; exiting");
        exit(44);
    }
    if (st_plat_persona_active()) {
        /* A handler path returned without ending its persona. Serving the next request
           as the wrong user is worse than any outage: stop, and let the pool loop
           start a clean process. */
        st_plat_log("persona still active after a request; exiting");
        exit(44);
    }
    st_resp_serialize(&resp, &cgi);
    st_fcgi_respond(out, conn->id, cgi.data, cgi.len);
    st_buf_free(&cgi);
    st_resp_free(&resp);
}

static void handle_connection(int fd)
{
    st_fcgi_conn conn;
    st_buf in, out;
    char chunk[16384];
    int closing = 0;

    st_fcgi_conn_init(&conn, PARAMS_LIMIT, BODY_LIMIT);
    /* Records are at most 8 + 65535 + 255 bytes; anything bigger in the buffer is a
       broken peer. */
    st_buf_init(&in, 2 * 65536 + 4096);
    st_buf_init(&out, 0);

    while (!closing) {
        long used;
        int k = (int) recv(fd, chunk, sizeof chunk, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        if (!st_buf_append(&in, chunk, (size_t) k)) break;
        for (;;) {
            st_fcgi_rec rec;
            int ev;
            used = st_fcgi_parse((const unsigned char *) in.data, in.len, &rec);
            if (used <= 0) break;
            ev = st_fcgi_conn_handle(&conn, &rec, &out);
            if (ev == ST_FCGI_READY) {
                int keep = conn.keep_conn;
                serve(&conn, &out);
                st_fcgi_conn_reset(&conn);
                if (!keep) closing = 1;
            } else if (ev == ST_FCGI_CLOSE) {
                closing = 1;
            }
            st_buf_consume(&in, (size_t) used);
            if (closing) break;
        }
        if (used < 0) closing = 1;
        if (out.len) {
            if (send_all(fd, out.data, out.len)) break;
            st_buf_reset(&out);
        }
    }
    st_fcgi_conn_free(&conn);
    st_buf_free(&in);
    st_buf_free(&out);
}

static int parse_bind(const char *spec, struct sockaddr_in *sa)
{
    char host[64];
    const char *colon = strrchr(spec, ':');
    long port;
    if (!colon || (size_t) (colon - spec) >= sizeof host) return -1;
    memcpy(host, spec, (size_t) (colon - spec));
    host[colon - spec] = '\0';
    port = strtol(colon + 1, NULL, 10);
    if (port <= 0 || port > 65535) return -1;
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((unsigned short) port);
    sa->sin_addr.s_addr = inet_addr(host);
    if (sa->sin_addr.s_addr == INADDR_NONE) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_in sa;
    st_app_config acfg;
    st_plat_config pcfg;
    st_err e;
    int lfd, one = 1;

    if (argc == 2 && !strcmp(argv[1], "-v")) {
        printf("steward %s\n", ST_VERSION);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "-g")) {
        /* DCL's F$UNIQUE is unique, not unpredictable: the secret comes from here. */
        unsigned char r[32];
        char hex[65];
        if (!st_plat_random(r, sizeof r)) { fprintf(stderr, "steward: no random numbers\n"); return 1; }
        st_hex(r, sizeof r, hex);
        st_zero(r, sizeof r);
        printf("%s\n", hex);
        st_zero(hex, sizeof hex);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "-b") || parse_bind(argv[2], &sa)) {
        fprintf(stderr, "usage: steward -b 127.0.0.1:<port> | -v | -g\n");
        return 2;
    }
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    acfg.idle_secs = env_long("STEWARD_IDLE_SECS", 900);
    acfg.absolute_secs = env_long("STEWARD_ABSOLUTE_SECS", 28800);
    acfg.cookie_secure = strcmp(env_str("STEWARD_INSECURE_COOKIE"), "1") != 0;
    acfg.trusted_proxies = env_str("STEWARD_TRUSTED_PROXIES");
    acfg.gateway_secret = env_str("STEWARD_GATEWAY_SECRET");
    if (*acfg.gateway_secret && strlen(acfg.gateway_secret) < 32) {
        fprintf(stderr, "steward: STEWARD_GATEWAY_SECRET must be at least 32 characters\n");
        return 1;
    }
    if (!*acfg.gateway_secret)
        fprintf(stderr, "steward: WARNING: no STEWARD_GATEWAY_SECRET; any local process "
                        "can reach this port directly\n");
    pcfg.audit_file = env_str("STEWARD_AUDIT_FILE");
    pcfg.session_file = env_str("STEWARD_SESSION_FILE");
    if (st_plat_init(&pcfg, &e)) {
        fprintf(stderr, "steward: platform init failed: %s\n", e.text);
        return 1;
    }
    st_app_init(&acfg);

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("steward: socket"); return 1; }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof one);
    if (bind(lfd, (struct sockaddr *) &sa, sizeof sa) || listen(lfd, 16)) {
        perror("steward: bind/listen");
        return 1;
    }
    fprintf(stderr, "steward %s: listening on %s\n", ST_VERSION, argv[2]);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        struct timeval tv;
        int fd = accept(lfd, (struct sockaddr *) &peer, &plen);
        if (fd < 0) { if (errno == EINTR) continue; perror("steward: accept"); continue; }
        if ((ntohl(peer.sin_addr.s_addr) >> 24) != 127) {
            st_plat_log("refused a connection from a non-loopback address");
            close(fd);
            continue;
        }
        tv.tv_sec = READ_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof tv);
        handle_connection(fd);
        close(fd);
    }
}
