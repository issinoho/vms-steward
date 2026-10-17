/* st_product.h - installed products (Phase 12, D20): parsers for what
   STEWARD_PRODUCT.COM writes, and for VMSINSTAL's history file. No I/O.

   PCSI has no documented interface to its database, so the D14 helper, which is the
   viewer, runs two PRODUCT commands into the reply mailbox, each in its part (PRODUCT
   needs the account authorized for SYSLCK, and switches it on itself; without it the
   part's status is %PCSIUI-E-PRIVCLASS1):

   %%PART%% PRODUCTS        PRODUCT SHOW PRODUCT/FULL
   ------------------------------------ ----------- --------- ----- ...
   PRODUCT                              KIT TYPE    STATE     MAINTENANCE  REFERENCED BY
   ------------------------------------ ----------- --------- ----- ...
   VSI X86VMS SSL3 V3.0-21              Full LP     Installed              ISSINOHO X86VMS ...
                                                                           VSI X86VMS TCPIP ...
   ------------------------------------ ----------- --------- ----- ...
   78 items found
   %%STATUS%% 00000001
   %%PART%% HISTORY         PRODUCT SHOW HISTORY/FULL: the same layout, other columns
   %%STATUS%% 00000001

   The dashed rule above the heading gives each column's start and width; the heading
   names them. A product is "<producer> <base> <name> <version>"; one longer than its
   column pushes the rest of its line right (VMSMARIADB V11.4-13E3 did), so the four
   words are taken as the product and the other columns shifted by the overflow. An
   indented line continues the row above: more maintenance, referenced-by or remark.
   PRODUCT's own messages ("%PCSIUI-E-PRIVCLASS1, operation requires SYSLCK
   privilege") are kept, the first of each part: their text is in the PRODUCT image,
   not a message file, so $GETMSG and F$MESSAGE give only %NONAME-E-NOMSG.

   VMSINSTAL's own record, SYS$UPDATE:VMSINSTAL.HISTORY, is a text file read in-process:
   a header, then one line per VMSINSTAL run with nine |-separated fields (name,
   mnemonic, version, date, status, IVP, node, installer, signature). Installs only,
   never removals. */
#ifndef ST_PRODUCT_H
#define ST_PRODUCT_H

#include <stddef.h>

enum { ST_PROD_PRODUCTS = 0, ST_PROD_HISTORY, ST_PROD_PARTS };

#define ST_PROD_COLS 12

typedef struct {
    int  part;                                      /* ST_PROD_PRODUCTS or _HISTORY */
    char producer[32], base[16], name[48], version[32];
    char kit_type[16];
    char state[16];                                 /* products */
    char maintenance[256], referenced_by[640];      /* products: ", " between items */
    char operation[16], validation[8], date[24], error[8], user[16], remark[128];   /* history */
} st_product;

typedef int (*st_product_cb)(const st_product *p, void *ctx);   /* nonzero stops */

typedef struct {
    st_product    cur;
    int           have, stopped, part;          /* part: -1 before the first marker */
    int           rules;                        /* dashed rules seen in this part */
    int           ncol;
    size_t        col_start[ST_PROD_COLS], col_width[ST_PROD_COLS];
    int           col_field[ST_PROD_COLS];      /* what each column holds: -1 nothing */
    int           seen[ST_PROD_PARTS];          /* its %%STATUS%% line came */
    unsigned int  status[ST_PROD_PARTS];
    char          message[ST_PROD_PARTS][256];  /* PRODUCT's first message, if any */
    st_product_cb fn;
    void         *ctx;
} st_product_parser;

void st_product_init(st_product_parser *p, st_product_cb fn, void *ctx);
/* One line, without its terminator. Returns 1 once the callback has stopped it. */
int  st_product_line(st_product_parser *p, const char *line, size_t len);
/* The end of the output: passes on the last row. */
int  st_product_end(st_product_parser *p);
/* Did part run and succeed? */
int  st_product_ok(const st_product_parser *p, int part);

typedef struct {
    char name[40], mnemonic[24], version[16], date[16];
    char status[8], ivp[8], node[16], installer[16], signature[16];
} st_vmsinstal;

/* One line of VMSINSTAL.HISTORY into v: 1 if it is a run, 0 for the header and
   anything else. */
int st_vmsinstal_line(const char *line, size_t len, st_vmsinstal *v);

#endif
