/* st_proc.h - processes (Phase 8, D16): input rules and names. No I/O.

   A PID is written as OpenVMS writes it: 8 hexadecimal digits, as SHOW SYSTEM lists
   it (0000751A), with or without the %X of STOP/ID=%X0000751A. */
#ifndef ST_PROC_H
#define ST_PROC_H

/* 1 if in is a PID, with it in *pid; 0 otherwise. Neither 0 nor FFFFFFFF is a PID:
   to $GETJPI and $DELPRC, -1 is the wildcard. */
int st_parse_pid(const char *in, unsigned int *pid);

/* The scheduling state's name as SHOW SYSTEM prints it (LEF, HIB, CUR, ...), from
   JPI$_STATE (SCH$C_*, 1 to 14 on x86 E9.2-4); "?" for anything else. */
const char *st_proc_state_name(int state);

/* What kind of process it is, from JPI$_MODE (JPI$K_OTHER 0, NETWORK 1, BATCH 2,
   INTERACTIVE 3) and whether it has an owner: "subprocess", "interactive", "batch",
   "network" or "detached". */
const char *st_proc_kind(int mode, int subprocess);

#include <stddef.h>

/* An image file's name and type, upper case, without device, directory or version:
   X86VMS$DKA0:[SYS0.SYSCOMMON.STEWARD.][BIN]STEWARD.EXE;1 is STEWARD.EXE. "" for "". */
void st_proc_image_name(const char *spec, char *out, size_t outlen);

#endif
