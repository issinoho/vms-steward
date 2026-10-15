/* st_proc.c - processes: input rules and names (st_proc.h). */
#include <string.h>
#include "st_proc.h"

int st_parse_pid(const char *in, unsigned int *pid)
{
    unsigned int v = 0;
    int i;
    if ((in[0] == '%') && (in[1] == 'X' || in[1] == 'x')) in += 2;
    if (strlen(in) != 8) return 0;
    for (i = 0; i < 8; i++) {
        char c = in[i];
        int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'A' && c <= 'F') ? c - 'A' + 10 :
                (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (d < 0) return 0;
        v = (v << 4) | (unsigned int) d;
    }
    if (!v || v == 0xFFFFFFFFu) return 0;
    *pid = v;
    return 1;
}

const char *st_proc_state_name(int state)
{
    /* SCH$C_COLPG 1 to SCH$C_CUR 14 (STATEDEF in SYS$LIB_C.TLB on the node). */
    static const char *const names[] = { "?", "COLPG", "MWAIT", "CEF", "PFW", "LEF", "LEFO",
        "HIB", "HIBO", "SUSP", "SUSPO", "FPG", "COM", "COMO", "CUR" };
    return state >= 1 && state <= 14 ? names[state] : "?";
}

const char *st_proc_kind(int mode, int subprocess)
{
    if (subprocess) return "subprocess";
    switch (mode) {
    case 3: return "interactive";
    case 2: return "batch";
    case 1: return "network";
    default: return "detached";
    }
}

void st_proc_image_name(const char *spec, char *out, size_t outlen)
{
    const char *start = spec, *p;
    size_t n = 0;
    for (p = spec; *p; p++)
        if (*p == ']' || *p == '>' || *p == ':') start = p + 1;
    for (p = start; *p && *p != ';' && n + 1 < outlen; p++)
        out[n++] = (*p >= 'a' && *p <= 'z') ? (char) (*p - 'a' + 'A') : *p;
    if (outlen) out[n < outlen ? n : outlen - 1] = '\0';
}

