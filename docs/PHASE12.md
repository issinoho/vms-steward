# Phase 12: installed products

**Status: planning (2026-10-16).** Probes done; the design (D20, proposed) and the
questions below are for the user. Nothing is built. Pick up from "Questions".

Read-only first (12a), as for the earlier areas. The user asked (2026-10-16) that
products installed by VMSINSTAL be reported too, not only PCSI's.

## What the probes found (NOTES.md)

| Source | Who may read it | How |
|---|---|---|
| PCSI: `PRODUCT SHOW PRODUCT/FULL`, `PRODUCT SHOW HISTORY/FULL` | only with **SYSLCK** on (STEWARD_TEST refused, %PCSIUI-E-PRIVCLASS1; SYSPRV does not do); the database files themselves are W:RE | DCL, no `/OUTPUT=`: `DEFINE/USER SYS$OUTPUT` instead |
| VMSINSTAL: `SYS$UPDATE:VMSINSTAL.HISTORY` | anyone (W:RE) | a text file, `|`-separated, installs only |

`probes/pcsi_view.com` is the PCSI probe (batch as STEWARD_TEST; the work account
with single privileges switched on).

## Proposed design (D20, not yet approved)

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

## Questions for the user (to settle before building)

1. **SYSLCK.** No test account holds it, and without it PCSI shows nothing. Authorize
   SYSLCK for STEWARD_ADM (the user runs it), or test PCSI only as the work account?
   And is a view that most users see as "needs SYSLCK" what you want, or should the
   PCSI part be offered only to viewers who hold it?
2. **VMSINSTAL's history** records installs only. Show it as history ("installed by
   VMSINSTAL on ...") rather than as the installed list?
3. **History:** include PCSI's install/remove history, or only what is installed now?
4. Changes (12b): decide later, as for SYSGEN and licences?
