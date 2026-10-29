# Changelog

Each release is a tag of this repository, and `v1` moves to the newest v1 release. Use `@v1` to get fixes as they
ship, or a release tag or its commit SHA to stay on one.

## v1.2 (2026-10-29)

For Valystrum v0.21.0 and later.

- `fail-on-error: true` also fails the job when Valystrum answers that it could not complete the scan (an `error` in
  its answer), when the answer cannot be read (a proxy's error page, an empty body), and when its code and IaC scanner
  did not finish the files sent. Left `false` (the default), each of these passes with a warning that says what was
  not checked. In v1.1 an answer carrying `error` read as a clean pass, and an unreadable answer failed the job
  whatever `fail-on-error` said.
- The job summary says what was checked: without the changed files' contents only secrets are scanned, since code
  analysis and the IaC checks need whole files.
- Sends the run's id, the commit's time and the repository's default branch, so Valystrum orders a branch's scans as
  GitHub ran them, and a scan of the default branch decides the findings of the files it read. A finding Valystrum
  recorded before v0.21.0 is closed only by a scan that sends these.
- A clone that holds only the commit built and cannot fetch its history no longer fails the job with a git error: it
  reports "No changes to scan" and passes.
- The example pins `actions/checkout` v7.0.1 by commit.

## v1.1 (2026-09-28)

- The stamped signature, `X-CS-Signature: t=<unix seconds>,v1=<HMAC-SHA256 over "<t>.<body>">`, signed again on
  every retry. Valystrum has refused the earlier `sha256=` form since 2026-09-28, so a release before v1.1 fails.
- Licensed under the Apache License 2.0.

## v1

The first release: secrets, code analysis (SAST) and IaC checks on a pull request's changed files, with the merge
blocked on a critical or high finding.
