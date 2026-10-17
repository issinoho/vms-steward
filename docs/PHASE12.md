# Phase 12: installed products

**Status: 12a closed (2026-10-17)** on the user's browser checks of 0.11.0. The user
approved D20 and the suggested answers below ("go with your suggestions").
**12b: install and remove, being built (2026-10-17)**: the user approved D26 and the
suggested answers ("Yes to all four"), the demo kit's install and removal on x86 among them.

Read-only first (12a), as for the earlier areas. The user asked (2026-10-16) that
products installed by VMSINSTAL be reported too, not only PCSI's.

## What the probes found (NOTES.md)

| Source | Who may read it | How |
|---|---|---|
| PCSI: `PRODUCT SHOW PRODUCT/FULL`, `PRODUCT SHOW HISTORY/FULL` | accounts authorized for **SYSLCK**, which PRODUCT switches on itself (STEWARD_TEST refused, %PCSIUI-E-PRIVCLASS1; SYSPRV does not do); the database files themselves are W:RE | DCL, no `/OUTPUT=`: `DEFINE/USER SYS$OUTPUT` instead |
| VMSINSTAL: `SYS$UPDATE:VMSINSTAL.HISTORY` | anyone (W:RE) | a text file, `|`-separated, installs only |

`probes/pcsi_view.com` is the PCSI probe (batch as STEWARD_TEST; the work account
with single privileges switched on).

## Design (D20, approved)

- **PCSI in the D14 helper**, a fourth fixed procedure `STEWARD_PRODUCT.COM`: `PRODUCT
  SHOW PRODUCT/FULL` and `PRODUCT SHOW HISTORY/FULL`, with `DEFINE/USER SYS$OUTPUT`
  the reply mailbox, between `%%PART%%`/`%%STATUS%%` markers as for licences. A viewer
  without SYSLCK sees PCSI's refusal (D10).
- **VMSINSTAL in-process**, read with RMS under the persona as access history reads its
  files (D13), parsed in core: no helper needed.
- `GET api/v1/products`: `pcsi` (installed products: producer, base, name, version,
  kit type, state, maintenance, referenced by), `pcsi_history`, `vmsinstal` (history
  lines), and `sources` with each refusal.
- Parsers in core: PCSI's columns from the dashed rule under the heading (widths vary;
  a long product name pushes the line right, so split on the rule widths only where
  the line fits, by tokens otherwise); VMSINSTAL's by `|`.

## Questions, settled 2026-10-16

1. **SYSLCK.** No test account holds it, and without it PCSI shows nothing. Authorize
   SYSLCK for STEWARD_ADM (the user runs it), or test PCSI only as the work account?
   And is a view that most users see as "needs SYSLCK" what you want, or should the
   PCSI part be offered only to viewers who hold it?
2. **VMSINSTAL's history** records installs only. Show it as history ("installed by
   VMSINSTAL on ...") rather than as the installed list?
3. **History:** include PCSI's install/remove history, or only what is installed now?
4. Changes (12b): decide later, as for SYSGEN and licences?

Answers (the suggestions, approved): 1. SYSLCK authorized, not default, for STEWARD_ADM
on x86 (the user runs AUTHORIZE); viewers without it see PCSI's refusal, by name. 2.
VMSINSTAL's record shown as history ("installed by VMSINSTAL on ..."). 3. PCSI's
install and remove history shown beside the installed list. 4. Changes later.

Found in testing (2026-10-17): PRODUCT switches SYSLCK on itself, so an account needs
only to be authorized for it (NOTES.md); the stub, page and tests follow that.

Live test: `tests/vms/phase12_live.py x86` 8 ok, 0 failed (STEWARD_TEST refused with
PRIVCLASS1; STEWARD_ADM, SYSLCK on or only authorized, the same 78 products and 527
history entries as PRODUCT SHOW; VMSINSTAL's 9 runs for both).

Kit T0.11-0 (0.11.0), built by `tools/kit.sh x86` (410 native checks), SHA-256
`b97a6286bb24a056f00674fef50deef033ce509a340ab8346bcfdff6ba5286ac`, for the browser
checks.

Closed 2026-10-17 on the user's browser checks of 0.11.0 ("kit installed, pool
restarted, looks good"). 12b, installing and removing products, is to be decided.

## 12b: install and remove (D26, proposed)

### What the probes found (read-only, x86, 2026-10-17)

- **Unattended**: `PRODUCT INSTALL` takes `/CONFIGURATION=PRODUCER` (the kit's own
  answers to its questions), `CURRENT` (the answers recorded when it was installed:
  the default, for an upgrade) or `INPUT=pcf`; `/OPTIONS=NOCONFIRM` drops the "are
  these the products" confirmation. Whether anything else prompts (an unsigned kit,
  a licence text, a product's own procedure) is not known without installing.
- **Finding kits**: `PRODUCT FIND * /SOURCE=<dir>` lists the kits in a directory, in
  the table PRODUCT SHOW uses (product, kit type, format), and needs no privilege; on
  a directory without kits, `%PCSIUI-I-NOMATCH`.
- **Privileges**: not stated by HELP. An install writes to the destination
  (SYS$COMMON by default), the PCSI database and SYSLCK-protected locks, and runs the
  kit's own procedures, which may need more (CMKRNL to INSTALL images, SYSNAM for
  system logical names). Known only by trying.
- **Time**: an install or removal can take minutes: far beyond the D14 helper's 30 s.

### Design

- **A batch job as the viewer.** The D14 helper (the viewer, short-lived) submits a
  fixed procedure, `STEWARD$ROOT:[COM]STEWARD_PCSI_JOB.COM`, to SYS$BATCH under the
  viewer's own username (no privilege needed to submit for oneself), with the
  operation, the product, the source directory and the privileges switched on in the
  session as parameters. The job switches those on (OpenVMS grants only what the
  account is authorized for, D9) and runs `PRODUCT INSTALL <product> /SOURCE=<dir>
  /CONFIGURATION=<CURRENT for an upgrade, PRODUCER otherwise> /OPTIONS=NOCONFIRM /LOG`
  or `PRODUCT REMOVE <product> /OPTIONS=NOCONFIRM /LOG`, logging to the viewer's
  SYS$LOGIN. The page follows the job (Phase 9's job view) and shows its log as it
  grows; the list of products is refreshed when it ends.
- **Kits from a directory on the node**, typed in the page: `PRODUCT FIND` lists what
  it holds, through the helper as the viewer, parsed as the product list is
  (`st_product.c`). No upload: request bodies stop at 256 KB, and kits run to hundreds
  of megabytes.
- **Refused by Steward**: Steward's own product (installing or removing it would stop
  or replace the pool running the request; do it at a terminal, as now), and the
  operating system (VSI ... VMS). Everything else is the manager's call, with what
  references it shown before a removal.
- **Validated twice**: names and the directory checked in core and again, character by
  character, in both procedures; nothing typed reaches DCL except as checked data.
- **API**: `GET api/v1/products/kits?source=`, `POST api/v1/products/install`
  (`{"product", "source"}`), `POST api/v1/products/remove` (`{"product"}`), each
  answering the job's entry; `GET api/v1/products/jobs/{entry}/log`. Audited.
- **Tests**: a kit of Steward's own making, `ISSINOHO <base> STWDEMO V1.0`, one text
  file, installed and removed through Steward as STEWARD_ADM with its destination in
  the work directory: it still adds an entry to the PCSI database and takes it away,
  a system-wide change only the user can allow (question 4).

Alternatives considered:
- **PRODUCT in the D14 helper directly**: no job to follow, but the 30 s deadline, and
  a request held for minutes.
- **The service runs PRODUCT**: its privileges, not the viewer's (D2).
- **Uploading kits**: the body limit, and a new path for large writes to the node.

## Questions for the user (12b)

1. **A batch job as the viewer**, followed in the page, as above?
2. **Kits from a directory typed in the page** (no upload)?
3. **Refuse Steward's own product and the operating system**, allow the rest?
4. **Testing**: may I build the demo kit and, through Steward as STEWARD_ADM, install
   and remove it on x86 (files in the work directory; an entry added to and removed
   from the PCSI database)? STEWARD_ADM may need more privileges authorized than it
   has (SYSPRV, SYSLCK); the first try will say which, and I would give you the
   AUTHORIZE command to run.

Suggested answers: 1 yes; 2 yes; 3 yes; 4 yes.

Answers (2026-10-17, "Yes to all four"): the suggestions, all four.

## Built (12b)

- `STEWARD_PCSI.COM` (the D14 helper: PRODUCT FIND, or SUBMIT) and
  `STEWARD_PCSI_JOB.COM` (the batch job: PRODUCT INSTALL or REMOVE, unattended); both
  check every value again. `GET api/v1/products/kits`, `POST .../install`, `POST
  .../remove`, `GET .../log` (api.md); the product list marks what Steward refuses.
- The page: Remove beside each product Steward allows, "Install from a kit directory"
  (PRODUCT FIND, then Install on a kit), the job's log followed every 2 s to its end;
  the name typed to confirm.
- What the first runs on x86 showed, each now handled (NOTES.md): STEWARD_ADM had no
  login directory (SUBMIT's status for it has no message text: the helper checks first,
  409) and no batch access (the job is refused at login, no log: Steward checks the
  UAF first, 409; the page explains a job gone without a log). PCSI needs CMKRNL,
  SYSLCK, SYSPRV and TMPMBX (PRIVCLASS3). The user created STEWARD_ADM's directory and
  gave it batch access and CMKRNL (authorized, not default) for the test.

Live test: `tests/vms/phase12b_live.py x86 SYSPRV,SYSLCK,CMKRNL` 12 ok, 0 failed: the
demo kit ISSINOHO X86VMS STWDEMO V1.0 found through Steward, NOMATCH for a directory
without kits, the operating system refused; the install submitted as STEWARD_ADM ran
to %X00000001 in about 13 s (PRODUCT SHOW lists it, its file in the destination), the
removal likewise (PRODUCT SHOW no longer lists it); staging, destination and job logs
removed after. Linux: 528 unit checks, the UI tests (Remove, kits, a job followed to its
end), `make audit`.
