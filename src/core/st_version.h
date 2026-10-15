/* st_version.h - the one place the release version is set. tools/kit.sh reads it
   for the PCSI kit (KIT.ENV) and the release name, so they cannot drift apart.

   ST_VERSION is semantic: major.minor.patch. ST_PCSI_VERSION is the same version
   in PCSI form: T for a field test (V for a full release), V<major>.<minor>-<patch>. */
#ifndef ST_VERSION_H
#define ST_VERSION_H

#define ST_VERSION      "0.8.0"
#define ST_PCSI_VERSION "T0.8-0"

#endif
