/* st_errlog.c - parsers for ELV's translation, CLUE's listings and OPCOM's log
   (Phase 14, D23). See st_errlog.h. */
#include <stdlib.h>
#include <string.h>
#include "st_errlog.h"

static const char *const months = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";

static void copy_trim(char *out, size_t outlen, const char *s, size_t n)
{
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    if (n >= outlen) n = outlen - 1;
    memcpy(out, s, n);
    out[n] = '\0';
}

/* The slice [from, to) of line (to < 0: to the end), trimmed. */
static void slice(char *out, size_t outlen, const char *line, size_t len, int from, int to)
{
    size_t a = from < 0 ? 0 : (size_t) from, b = to < 0 ? len : (size_t) to;
    if (b > len) b = len;
    if (a >= b) { out[0] = '\0'; return; }
    copy_trim(out, outlen, line + a, b - a);
}

static int isdig(char c) { return c >= '0' && c <= '9'; }

void st_vms_time_iso(const char *v, char iso[20])
{
    int i = 0, day, mon;
    const char *m;
    char mm[4];
    iso[0] = '\0';
    if (!isdig(v[0])) return;
    day = v[0] - '0';
    i = 1;
    if (isdig(v[1])) { day = day * 10 + (v[1] - '0'); i = 2; }
    if (v[i] != '-' || day < 1 || day > 31) return;
    memcpy(mm, v + i + 1, 3);
    mm[3] = '\0';
    if (strlen(mm) != 3) return;
    m = strstr(months, mm);
    if (!m || (m - months) % 3) return;
    mon = (int) (m - months) / 3 + 1;
    v += i + 4;   /* "-YYYY HH:MM:SS" */
    if (v[0] != '-' || !isdig(v[1]) || !isdig(v[2]) || !isdig(v[3]) || !isdig(v[4]) || v[5] != ' ' ||
        !isdig(v[6]) || !isdig(v[7]) || v[8] != ':' || !isdig(v[9]) || !isdig(v[10]) || v[11] != ':' ||
        !isdig(v[12]) || !isdig(v[13]))
        return;
    iso[0] = v[1]; iso[1] = v[2]; iso[2] = v[3]; iso[3] = v[4]; iso[4] = '-';
    iso[5] = (char) ('0' + mon / 10); iso[6] = (char) ('0' + mon % 10); iso[7] = '-';
    iso[8] = (char) ('0' + day / 10); iso[9] = (char) ('0' + day % 10); iso[10] = 'T';
    memcpy(iso + 11, v + 6, 8);
    iso[19] = '\0';
}

/* ================================================================ ELV */

void st_elv_init(st_elv_parser *p, st_elv_event_cb ev, st_elv_field_cb fl, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->event_fn = ev;
    p->field_fn = fl;
    p->ctx = ctx;
    p->part = -1;
}

/* A heading's words: their starts (and widths) in order, n of them. */
static int heading(const char *line, size_t len, int *start, int *width, int max)
{
    size_t i = 0;
    int n = 0;
    while (i < len && n < max) {
        size_t s;
        while (i < len && line[i] == ' ') i++;
        if (i >= len) break;
        s = i;
        while (i < len && line[i] != ' ') i++;
        start[n] = (int) s;
        if (width) width[n] = (int) (i - s);
        n++;
    }
    return n;
}

static int starts(const char *line, size_t len, const char *word)
{
    size_t n = strlen(word);
    return len >= n && !memcmp(line, word, n);
}

static void elv_message(st_elv_parser *p, const char *line, size_t len)
{
    char m[200];
    copy_trim(m, sizeof m, line, len);
    if (!p->message[0]) {
        size_t n = strlen(m);
        if (n >= sizeof p->message) n = sizeof p->message - 1;
        memcpy(p->message, m, n);
        p->message[n] = '\0';
    } else if (m[0] == '-' && !strstr(p->message, m) && strlen(p->message) + strlen(m) + 3 < sizeof p->message) {
        /* ELV writes its message to both SYS$OUTPUT and SYS$ERROR: once is enough. */
        strcat(p->message, " / ");
        strcat(p->message, m);
    }
}

void st_elv_line(st_elv_parser *p, const char *line, size_t len)
{
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (starts(line, len, "%%PART%% ")) {
        p->part = starts(line + 9, len - 9, "ENTRY") ? ST_ELV_ENTRY : ST_ELV_LIST;
        p->seen = 1;
        p->in_fields = 0;
        p->ec[0] = -1;
        p->fc[0] = -1;
        return;
    }
    if (starts(line, len, "%%STATUS%% ")) {
        char hex[16];
        copy_trim(hex, sizeof hex, line + 11, len - 11);
        p->status = (unsigned int) strtoul(hex, NULL, 16);
        p->status_seen = 1;
        p->part = -1;
        return;
    }
    if (p->part < 0 || p->stop) return;
    if (len == 0 || strspn(line, " ") == len) { if (p->in_fields) p->blank = 1; return; }
    /* ELV's (or DCL's) messages: "%FAC-S-IDENT, text" and its "-FAC-S-IDENT" lines. */
    if ((line[0] == '%' && len > 1 && line[1] != '%') ||
        (line[0] == '-' && len > 2 && line[1] >= 'A' && line[1] <= 'Z')) {
        elv_message(p, line, len);
        return;
    }
    if (starts(line, len, "EVENT ") && strstr(line, "EVENT_TYPE_")) {
        int w[5];
        if (heading(line, len, p->ec, w, 5) == 5) memcpy(p->ew, w, sizeof w);
        else p->ec[0] = -1;
        return;
    }
    if (starts(line, len, "DESCRIPTION_")) {
        int w[4];
        if (heading(line, len, p->fc, w, 4) == 4) {
            p->in_fields = 1;
            p->blank = 0;
            p->fc[0] = w[0];   /* kept as the description's width: its column starts at 0 */
        } else {
            p->fc[0] = -1;
        }
        return;
    }
    if (p->ec[0] >= 0 && isdig(line[0]) && !p->in_fields) {
        st_elv_event ev;
        char num[16];
        memset(&ev, 0, sizeof ev);
        slice(num, sizeof num, line, len, 0, p->ec[1]);
        if (!isdig(num[0]) || strspn(num, "0123456789") != strlen(num)) return;
        ev.number = (unsigned int) strtoul(num, NULL, 10);
        slice(ev.type, sizeof ev.type, line, len, p->ec[1], p->ec[2]);
        slice(ev.when, sizeof ev.when, line, len, p->ec[2], p->ec[3]);
        slice(ev.node, sizeof ev.node, line, len, p->ec[3], p->ec[4]);
        slice(ev.cls, sizeof ev.cls, line, len, p->ec[4], -1);
        st_vms_time_iso(ev.when, ev.iso);
        p->nevents++;
        if (p->event_fn && p->event_fn(&ev, p->ctx)) p->stop = 1;
        return;
    }
    if (p->in_fields && p->fc[0] > 0 && line[0] == ' ') {
        st_elv_field f;
        size_t lead = strspn(line, " "), k;
        int gap_text = 0;
        memset(&f, 0, sizeof f);
        f.group = p->blank;
        p->blank = 0;
        /* Text across the gap between the description and RANGE: free text. */
        for (k = (size_t) p->fc[0]; k < (size_t) p->fc[1] && k < len; k++)
            if (line[k] != ' ') { gap_text = 1; break; }
        if (gap_text) {
            f.text = 1;
            copy_trim(f.description, sizeof f.description, line, len);
        } else {
            f.indent = lead >= 3 ? (int) (lead - 3) / 3 : 0;
            slice(f.description, sizeof f.description, line, len, 0, p->fc[1]);
            slice(f.range, sizeof f.range, line, len, p->fc[1], p->fc[2]);
            if ((size_t) p->fc[3] < len && line[p->fc[3] - 1] != ' ') {
                /* A value longer than its column ("QEMU Standard PC (Q35 + ICH9, *"):
                   it runs on, and there is no translation. */
                slice(f.value, sizeof f.value, line, len, p->fc[2], -1);
            } else {
                slice(f.value, sizeof f.value, line, len, p->fc[2], p->fc[3]);
                slice(f.translated, sizeof f.translated, line, len, p->fc[3], -1);
            }
            if (!f.range[0] && !f.value[0] && !f.translated[0] && lead < 3) f.text = 1;
        }
        p->nfields++;
        if (p->field_fn && p->field_fn(&f, p->ctx)) p->stop = 1;
    }
    /* Anything else ("Output for ...", the summary's lines): not ours. */
}

int st_elv_refused(const st_elv_parser *p)
{
    return p->message[0] && (strstr(p->message, "-E-") || strstr(p->message, "-F-"));
}

/* ================================================================ CLUE */

void st_clue_init(st_clue_summary *s) { memset(s, 0, sizeof *s); }

void st_clue_line(st_clue_summary *s, const char *line, size_t len)
{
    const char *colon;
    char key[64];
    size_t k, klen;
    if (s->done) return;
    if (++s->lines > 120) { s->done = 1; return; }
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (!len || line[0] == ' ') return;
    colon = memchr(line, ':', len);
    if (!colon) return;
    klen = (size_t) (colon - line);
    if (klen == 0 || klen >= sizeof key) return;
    for (k = 0; k < klen; k++) {
        char c = line[k];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isdig(c) || c == ' ' || c == '/' ||
              c == '$' || c == '_' || c == '.'))
            return;
    }
    copy_trim(key, sizeof key, line, klen);
    if (!strcmp(key, "Stack Pointers") || !strcmp(key, "General Registers")) { s->done = 1; return; }
    if (s->nitems >= ST_CLUE_MAX_ITEMS || strlen(key) >= sizeof s->items[0].key) return;
    copy_trim(s->items[s->nitems].value, sizeof s->items[0].value, colon + 1, len - klen - 1);
    if (!s->items[s->nitems].value[0]) return;   /* a heading ("Crashdump Summary Information:") */
    strcpy(s->items[s->nitems].key, key);
    s->nitems++;
}

const char *st_clue_get(const st_clue_summary *s, const char *key)
{
    int i;
    for (i = 0; i < s->nitems; i++)
        if (!strcmp(s->items[i].key, key)) return s->items[i].value;
    return "";
}

int st_valid_clue_name(const char *name)
{
    size_t n = strlen(name), i;
    if (n < 21 || n > 39 || strncmp(name, "CLUE$", 5) || strcmp(name + n - 4, ".LIS")) return 0;
    /* <node>_<ddmmyy>_<hhmm> between */
    for (i = 5; i < n - 4; i++) {
        char c = name[i];
        if (!((c >= 'A' && c <= 'Z') || isdig(c) || c == '_')) return 0;
    }
    if (name[n - 9] != '_' || name[n - 16] != '_') return 0;
    for (i = n - 15; i < n - 9; i++) if (!isdig(name[i])) return 0;
    for (i = n - 8; i < n - 4; i++) if (!isdig(name[i])) return 0;
    return 1;
}

/* ================================================================ OPCOM */

#define OPCOM_HEAD "%%%%%%%%%%%  OPCOM  "

void st_opcom_init(st_opcom_parser *p, st_opcom_cb fn, void *ctx)
{
    memset(p, 0, sizeof *p);
    p->fn = fn;
    p->ctx = ctx;
}

static void opcom_emit(st_opcom_parser *p)
{
    size_t n;
    if (!p->open || p->stop) { p->open = 0; return; }
    n = strlen(p->cur.text);
    while (n && p->cur.text[n - 1] == '\n') p->cur.text[--n] = '\0';
    p->cur.stamp = !strcmp(p->cur.text, "Logfile time stamp");
    if (p->fn && p->fn(&p->cur, p->ctx)) p->stop = 1;
    p->open = 0;
}

void st_opcom_line(st_opcom_parser *p, const char *line, size_t len)
{
    size_t hl = strlen(OPCOM_HEAD);
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (len >= hl + 23 && !memcmp(line, OPCOM_HEAD, hl)) {
        opcom_emit(p);
        memset(&p->cur, 0, sizeof p->cur);
        copy_trim(p->cur.when, sizeof p->cur.when, line + hl, 23);
        st_vms_time_iso(p->cur.when, p->cur.iso);
        p->open = 1;
        return;
    }
    if (!p->open) return;
    if (!p->cur.text[0] && !p->cur.from[0] && starts(line, len, "Message from user ")) {
        const char *s = line + 18, *on = NULL, *e = line + len;
        const char *q;
        for (q = s; q + 4 <= e; q++) if (!memcmp(q, " on ", 4)) { on = q; break; }
        if (on) {
            copy_trim(p->cur.from, sizeof p->cur.from, s, (size_t) (on - s));
            copy_trim(p->cur.node, sizeof p->cur.node, on + 4, (size_t) (e - on - 4));
            return;
        }
    }
    if (!len && !p->cur.text[0]) return;
    {
        size_t have = strlen(p->cur.text), room = sizeof p->cur.text - 1 - have;
        if (have && room) { p->cur.text[have++] = '\n'; room--; }
        if (len > room) len = room;
        memcpy(p->cur.text + have, line, len);
        p->cur.text[have + len] = '\0';
    }
}

void st_opcom_end(st_opcom_parser *p) { opcom_emit(p); }
