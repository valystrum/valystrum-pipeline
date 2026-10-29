# Valystrum Security Pipeline Action

Scans a pull request for **leaked secrets**, **code vulnerabilities (SAST)** and **IaC
misconfiguration**, and blocks the merge on critical/high findings. Results appear inline on the
PR's Files tab, in the job summary, as a PR comment (with `github-token`), and in Valystrum's
**Dev Pipeline** module and **Findings** register. Pipeline security is part of the Gold plan and
above. This action is licensed under the Apache License 2.0 ([LICENSE](LICENSE)); the Valystrum
platform it calls is not.

Same shape as [`valystrum/valystrum-sbom`](https://github.com/valystrum/valystrum-sbom): one step, one
repository secret, HMAC-signed.

Not on GitHub? The same scan, with the same request, signature, retries and fail-open rule, comes for
GitLab CI/CD ([gitlab.com/valystrum/valystrum-gitlab-ci](https://gitlab.com/valystrum/valystrum-gitlab-ci)), Azure
Pipelines ([github.com/valystrum/valystrum-azure-pipelines](https://github.com/valystrum/valystrum-azure-pipelines)),
AWS CodeBuild and CodePipeline ([github.com/valystrum/valystrum-aws-codebuild](https://github.com/valystrum/valystrum-aws-codebuild))
and Google Cloud Build ([github.com/valystrum/valystrum-cloud-build](https://github.com/valystrum/valystrum-cloud-build)).
Google Cloud Build numbers no builds, so there the scans of a branch are ordered by the commit's time unless you set a
run number of your own, and a force-push back to an older commit counts as the older scan.


```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0   # the scan diffs against the base branch

- uses: valystrum/valystrum-pipeline@v1
  with:
    webhook-url: https://app.valystrum.io/api/v1/<org>/pipeline/scan
    webhook-secret: ${{ secrets.CS_WEBHOOK_SECRET }}
```

## What actually runs

Three engines, one findings list. Each finding carries a `kind`, a rule id, `file:line`, a
remediation hint and a CWE where the rule has one.

| Kind | Engine | Covers |
|---|---|---|
| `sast` | Opengrep over a licence-clean rule pack (GitLab's MIT / Apache-2.0 / LGPL-3.0 rules, 422 files) | JS/TS, Python, Java, Go, C#, Scala, Kotlin, Swift, Objective-C |
| `iac` | Trivy's embedded misconfiguration checks, medium and above | Terraform, CloudFormation, Azure Resource Manager templates (JSON), Kubernetes, Helm, Dockerfile |
| `secret` | Valystrum's secret scanner over the diff's added lines | AWS keys, GitHub/Slack tokens, Stripe live keys, private keys, Google API keys, JWTs, generic API keys |

The rules are **not** maintained by you: they are vendored into the platform's scanner image at a
pinned upstream commit, and they change only when Valystrum moves that pin (or the pinned Opengrep
and Trivy versions) and rebuilds the image.

Not covered: Ruby, PHP and C. GitLab's pack has no MIT, Apache-2.0 or LGPL-3.0 rules for Ruby or
PHP, and its C rules are GPL-2.0, which the platform does not vendor. Also not covered: a file whose path git
writes in quotes (by default, a path with a non-ASCII character, a double quote, a backslash or a control character).
Its lines are not scanned for secrets, it is not sent for code analysis or the IaC checks, and nothing in the job's
log or summary names it.

Secret severities: AWS access keys, GitHub tokens, Stripe live keys and private keys are critical;
Google API keys and Slack tokens are high; JWTs and generic API keys are medium, so those two are
reported but do not block a merge. The secret scan reads only the lines a change adds. It skips
lockfiles; generated or vendored directories (`node_modules/`, `vendor/`, `dist/`, `build/`,
`out/`, `coverage/`, `.next/`); minified, `.snap` and `.map` files; and `*.example`, `*.sample`,
`*.template` and `*.dist` files. It ignores values that read as placeholders (`example`, `xxxx`,
`placeholder`, `changeme`, `your_key`, `dummy`, `redacted`, `<…>`).

**Code analysis and the IaC checks need file contents.** The engines parse whole files, and a unified
diff carries only hunks, so this action sends the changed files alongside the diff
(`send-file-contents`, on by default). With it off, or above the size cap, the platform scans secrets only, and says so (`scanned.checks` is `["secrets"]`, the job
summary and the PR comment name what was skipped) rather than reporting a silent zero.

## Setup

The action runs in `bash` on the runner and needs `git`, `jq`, `curl`, `openssl` and `base64`.
GitHub-hosted runners have them; install them on a self-hosted runner.

**1. Get the CI secret** (once per repository; if you already run the SBOM action for this repo,
you have it and can skip to step 2). An organisation owner or admin issues it under
**Settings → CI pipeline keys** in Valystrum. Issuing a key again there for the same repository
rotates its secret, and every workflow signing with the old one (the SBOM action included) then
gets HTTP 401 `Invalid signature`. An owner or admin can also call the endpoint with their
signed-in session's cookie (an auditor API key is read-only and is refused). Each named repository
counts against the plan's repository allowance (see **Managing keys** below).

```bash
curl -X POST https://app.valystrum.io/api/v1/<org>/pipeline/config \
  -H "content-type: application/json" -H "cookie: <your signed-in session cookie>" \
  -d '{"repo": "acme/web-api"}'
```

The response contains `webhookSecret` (`cs_wh_…`), shown **once**. Re-running the call does not
rotate it unless you pass `{"repo": "acme/web-api", "regenerateSecret": true}`.

**2. Add it as a repository secret** (`Settings → Secrets and variables → Actions`), named
`CS_WEBHOOK_SECRET`. Pull requests from forks and from Dependabot cannot read it (see
Troubleshooting).

**3. Copy [`examples/security-scan.yml`](examples/security-scan.yml)** to
`.github/workflows/security-scan.yml` and replace `acme` in the `webhook-url` with your org slug.
The example also scans every push to `main`; if your default branch has another name, change
`branches: [main]` to it. A push run diffs against the commit before the push and posts no PR comment; its
results are in the job summary and in Valystrum. The push runs on the default branch are how Valystrum's
default-branch rule (see [What a later scan closes](#what-a-later-scan-closes)) reads your code. The action takes your
default branch's name from the event (`github.event.repository.default_branch`), not from the workflow, so a push
trigger on another branch leaves the default branch unread.

**4. Make the job a required status check** on the target branch (branch protection or a
ruleset). The action fails the job; only a required check keeps a pull request with a failed job
from being merged.

**Managing keys.** `GET /api/v1/<org>/pipeline/config` lists the active keys (never their secrets),
and **Settings → CI pipeline keys** lists and revokes them too. `PATCH .../pipeline/config/<keyId>`
changes a key's repository or label and leaves its secret alone, and
`DELETE .../pipeline/config/<keyId>` revokes it. Gold includes 100 repositories and Enterprise is
custom. From Gold, 25 more repositories are an add-on at €100 a month or €1,000 a year. Rotating or
relabelling a key never spends a slot, revoking one returns its slot, and a new repository over the
allowance is refused with `QuotaExceeded`. Every key names its repository: a call without `repo` is refused with
HTTP 400. A repository without a key of its own gets HTTP 401 `Invalid signature: sign with this repository's CI key`
on every run, which the action prints as an error and, with `fail-on-error: false` (the default), passes: nothing is
scanned and no finding closes until it signs with a key of its own.

The organisation-wide key is retired. A key issued without a repository shows under **Settings → CI pipeline keys** as
"organisation-wide (retired: no scan accepts it, revoke it)", and the **Dev Pipeline** module lists a repository that
signed with it as "no key" (or "never analysed" while none of its scans ran code analysis), and its own page says it
has no key of its own. Issue a key for each repository that still signs with it (step 1, one repository of the
allowance each) and put its secret in that repository's `CS_WEBHOOK_SECRET`. The SBOM action signs with the same
secret, so it needs the new one too. Then revoke the organisation-wide key.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `webhook-url` | yes | none | `https://app.valystrum.io/api/v1/<org>/pipeline/scan` |
| `webhook-secret` | yes | none | Repository CI secret (`cs_wh_…`) |
| `base-ref` | no | the pull request's base SHA; on a push, the commit before the push | Ref to diff against. The first push of a new branch diffs against the parent commit (`HEAD~1`); a base not in the clone falls back to it too, with a warning |
| `paths` | no | none | Space-separated pathspecs that limit the diff, and so the secret scan, e.g. `infra/ app/`. The changed files sent for code analysis and the IaC checks are not limited by it: every changed file is sent, within the size caps |
| `send-file-contents` | no | `true` | Send changed files so code analysis and the IaC checks can run; without them only secrets are scanned |
| `fail-on-findings` | no | `true` | Fail the job when the scan reports `passed=false` |
| `fail-on-error` | no | `false` | Fail the job when the scan endpoint is unreachable or refuses the request, answers that it could not complete the scan (`error` in the answer), or did not finish checking the files it was sent (its code and IaC scanner timed out, failed or is not configured) |
| `github-token` | no | none | Lets Valystrum post the findings as one comment on the pull request, updated in place on each run (none on a push run). The token travels inside the signed request and is used to post the comment, never stored |

## Outputs

| Output | Description |
|---|---|
| `passed` | `'true'` when no critical/high finding was reported |
| `findings` | Number of findings |
| `scan-id` | Valystrum scan id |

When the endpoint did not answer 200, answered that it could not complete the scan, or there was
nothing to scan, `passed` is `'true'` and `findings` is `0` (`scan-id` is empty or the id the answer
gave). No output says which checks ran: read the job's warning and summary, or set
`fail-on-error: true`, before treating `passed` as a clean scan.

## What blocks a merge

`passed` is `false` when **any critical or high** finding is present, of any kind, and the job then
fails (`fail-on-findings: true`). Opengrep severities map to Valystrum's four levels (ERROR→high,
WARNING/MEDIUM→medium, INFO→low), with directly exploitable weakness classes
(CWE-78/89/94/95/502/798/918: command and SQL injection, code injection, unsafe deserialization,
hardcoded credentials, SSRF) raised to **critical**. Code analysis and the IaC checks read each changed file whole,
so a critical or high finding already in a file the change touches fails the job too, even on a line the change did
not touch. The secret scan reads only the lines the change adds.

**A scanner outage never blocks you, unless you ask it to.** A scan the platform could not complete
still answers HTTP 200, with `passed: true` and an `error` (`scan_error`): nothing was checked, and
the job passes with a warning that says so. A 200 whose body is not a JSON object (a proxy's page,
an empty body) is read the same way, as `unreadable answer`. Any other answer (a 401, 403, 413 or
429, or no answer at all) is printed as an error in the job log and treated as a pass. When the files went but the
platform's code and IaC scanner timed out, failed or is not configured, the answer carries no
`error`: `scanned.sastStatus` says which, `scanned.checks` names only the checks that finished (a
finding from the one that did still gates the merge), and the job passes with a warning naming what
ran. `fail-on-error: true` fails the job on all three, the last once the summary and the findings are
written. Set it once the setup works, or a rotated secret, a plan change or a scanner fault turns
the gate off without failing a build.

Each finding is also recorded as a Finding in Valystrum, one per repository, rule and file. A later scan that still trips the rule refreshes it, and reopens it if it was resolved ([What a later scan
closes](#what-a-later-scan-closes) says which scans count, and what one that no longer finds it does). Resolving or
accepting a finding in Valystrum does not change the gate: every scan is judged on its own findings,
so the next change that still carries a critical or high one fails too.

When the most severe IaC finding names a resource Valystrum knows (a cloud resource or an asset
whose name contains it), the PR comment adds a blast radius. It counts the records related directly
to that resource and your organisation's failing automated controls (at most ten), which are not
only those tied to it. The comment lists the three most severe findings, and the job summary the
twenty most severe; the rest are in Valystrum under the scan id.

### What a later scan closes

A scan that read a file in full and no longer finds a finding there closes it; a secret stays open and asks you to
confirm its rotation. What counts as read: a file the change deletes, for every kind of finding, secrets included; a code or
IaC file the action sent whole whose engine finished and could parse it; and, for a secret, a file the action sent
whole that the secret scan does not skip, which Valystrum reads again in full (the scan itself reads only the added
lines). So a scan without file contents closes only a deleted file's findings, and an engine that timed out or failed
closes nothing of its kind. A Terraform file in a local module counts when Trivy loaded that module, so a module
called with `count = 0` or an empty `for_each` is not read.

A closed finding is resolved with the note `Fixed: not found by the code scan of <day>`, and its open remediation
items move to ready for verification (a linked Jira or ServiceNow ticket gets the note as a comment), for a person to
verify and close. The close is not waited for: Valystrum answers the job without it, so neither the job's result, its
summary nor the PR comment says what closed. A close that fails is not retried: what it would have closed stays open
until a later scan of a deciding branch reads the file in full again, or until you resolve it. A finding you accepted
or marked a false positive is never closed or reopened by a scan. One you reopened by hand stays open until a scan
finds it again, and only a later scan that no longer finds it closes it.

A finding a later scan finds again after it was closed (a scan of a branch that decides it, see below) is reopened,
and its remediation items waiting for verification go back to in progress, with a comment on their Jira or
ServiceNow ticket that the fix did not hold. An item a person closed stays closed.

A leaked secret recorded in **Data Security → Secrets** follows the same rule (and the branch rule below): when a
scan deletes its file, or sends
that file whole without the secret, and no other file the scan sent whole still holds the same value (for a private
key, only its own file counts, under its new name when the change renamed it), the finding copied from it into the
register (see [Secrets are never echoed](#secrets-are-never-echoed)) asks you to confirm the rotation, as a pipeline
secret does. A scan never closes it.

The action sends the run's id (`sequence`, `github.run_id`), the commit's time (`committedAt`) and your repository's default branch
(`defaultBranch`). `committedAt` is the checked-out commit's committer time as git records it (on a pull request,
that of the merge commit GitHub prepares for it), and one later than Valystrum's clock counts as now. A pull
request's scan is recorded under its head branch (`github.head_ref`) and a push run under the pushed branch, so a
pull request's runs and the push runs of its branch are that one branch's scans. Two scans of one branch are taken
in run order, so an older push that finishes last neither reopens nor closes what a newer scan decided, a force-push
back to an older commit is still the newer scan, and a re-run of an old run stays old; the commit's time orders two
scans only when one of them sent no run id. Run ids are compared as numbers whichever CI sent them, so scan each
repository from one CI system: GitHub's run id beside another system's build number orders the branch by whichever
is larger, not by when its commits were made.

Once a scan of the default branch has read a finding's file since the finding was raised (found it there, or read
the file whole without it), the default branch decides that finding, so a pull request or an old branch that still
carries a finding fixed on the default branch neither reopens nor holds it. Until then (so also for a finding a
branch raised after the default branch last read its file), every branch whose scan read the file holds its findings
while that branch's latest scan still finds them, and a finding closes only when none does. So a fix closes a
finding when it reaches the default branch; a pull request's own scan that no longer finds it closes it only while
the default branch has not read the file since the finding was raised and no other branch still finds it.

The default branch decides only for the scans that name it. A scan whose request carries no `defaultBranch` is
judged as though the repository had none, even for a file the default branch has read: if its branch still has a
finding the default branch fixed, it reopens it, and it closes a finding only when no branch's latest scan still
finds it. So run v1.2 or later in every workflow that runs this action on the repository (a second workflow or a
commit pin still on v1.1 sends none). The action takes the name from the event's repository, so a run
on an event that carries none (a `schedule` run) sends none either.

Run the job on `push` to the default branch as well as on pull requests (`examples/security-scan.yml` does, for a
default branch named `main`) so the default branch reads each file a push to it changes (a push run diffs against
the commit before the push). Deleting a branch tells Valystrum nothing: a finding raised on a branch that is never
merged stays open until a scan of the default branch reads that file, or until you resolve it. A finding recorded
before v0.21.0 has no branch on record until a scan finds it again, and until then it closes only when a scan of the
default branch reads its file. The **Dev Pipeline** module says why each pipeline finding is still open: still found
by its branch's latest scan (or found again after it was resolved), still on another branch (naming the branches that
still have it), reopened by a person, no branch on record, not checked again since it was last reported, or a secret
whose rotation you have to confirm.

A renamed or moved file takes its findings along to its new path, a finding you accepted or marked a false positive
included, with your verdict. Git has to report the change as a rename (the `rename from` and `rename to` lines of the
diff). A file edited so much that git reads it as a deletion and a new file (by default, when less than half of it
is kept), or one moved into or out of the `paths` you limit the diff to, is not moved: the new path's findings are
raised afresh, and the old path's close as a deleted file's when the diff shows it deleted (a file moved into your
`paths` from outside them leaves them open, since the diff does not show its old path). The move is made by a scan
of a branch that decides the finding, so once your default branch has read the old file, a pull request that renames
it moves nothing: its scan raises what it still finds
under the new path as new findings. When the change reaches the default branch, the old path's open findings close
as fixed, although the code only moved, and the new ones stay open. Whenever a file's findings do not move, one you
accepted or marked a false positive stays on the old path. If a move fails, the old path's findings stay open where
they were, and the next scan of the repository moves them (the next completed scan on any branch, up to twenty
failed scans' moves at a time, oldest first). If the failed scan could not keep its renames either, nothing is
retried, and the old path's findings stay open until you resolve them.

## Secrets are never echoed

A detected credential is reported as a masked preview (`AKIA••••3456`), never the raw value.
Findings are printed into job logs and public PR comments, so the raw secret is redacted before it
ever leaves the platform. Detections also land in **Data Security → Secrets** in Valystrum, scoped
to this repository and its file, so the same key leaked in two repositories, or in two files of one repository,
stays two findings. Each of those rows also raises a finding of its own in **Findings** ("Exposed secret (…) in
ci:owner/name"), beside the pipeline finding, so a leaked secret shows there twice. When the scan that decides it no
longer finds the secret, both stay open and ask you to confirm the rotation, and you close each.

## What Valystrum keeps

The diff and the changed files themselves are scanned and not kept. The scanner writes the files
to a temporary directory in memory and deletes it when the scan ends. Valystrum keeps the scan
record: repository, branch, pull request, commit SHA and the commit's time, the CI run's id, the default branch, the
verdict, each finding (rule id, `file:line`, the rule's message, which a rule can write to name the flagged
expression, and its remediation hint; a secret only as its masked preview), what was checked and the blast radius,
and, when a renamed file's findings could not be moved, the old and new paths until a later scan moves them. It is
kept for as long as your organisation exists in Valystrum. Each finding is also kept as a Finding in the Findings
register (see [What blocks a merge](#what-blocks-a-merge)), handled like any other finding there, with every branch's
latest read of its file (the branch, the commit's time or the arrival, the run's id, and whether the finding was
there), and a leaked secret in Data Security → Secrets as its masked preview, its location and a one-way
fingerprint. On a pull request the commit is the merge commit GitHub prepares for it (`GITHUB_SHA`, and that commit's
time), not your branch's head.

`GET /api/v1/<org>/pipeline/scans/<scan-id>` (with a signed-in session or an auditor API key, on Gold and above)
answers a scan's record with its `committedAt`, `sequence` and `defaultBranch`, each `null` when the action did not
send it; `GET /api/v1/<org>/pipeline/scans` lists scans without them. The scan id is the action's `scan-id` output.

## Size limits

The signed body is capped at 2 MB. File contents are capped at **300 files, 512,000 bytes (500 KB)
each and about 1.5 MB in total**; a file that would go over a cap is not scanned, and binary files
are never sent (the action sends a file of up to 524,288 bytes, but the scanner skips one over
512,000). If the payload still exceeds 2 MB the action drops the file contents before sending, and
then only secrets are scanned: no code analysis and no IaC check. `paths` shrinks the diff on a very
large PR, not the files sent (see Inputs).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `webhook-secret is empty` (the job fails whatever `fail-on-error` says) | The workflow could not read `CS_WEBHOOK_SECRET`. Either the secret's name differs from the one in your workflow, or the run is a pull request from a fork or from Dependabot. GitHub gives neither your repository's Actions secrets. Add the secret under Dependabot secrets as well, and skip the job for forks while keeping push runs (`if: github.event_name != 'pull_request' \|\| github.event.pull_request.head.repo.full_name == github.repository`) |
| `No changes to scan` | The diff is empty: nothing changed under `paths`, or the action could not deepen a shallow clone to reach the base commit. Set `fetch-depth: 0` on `actions/checkout` |
| `Base ref '…' is not in this clone; falling back to HEAD~1` | The base commit could not be fetched, so only the last commit was scanned. Set `fetch-depth: 0` |
| Every run warns `could not complete the scan (scan_error)` and nothing is checked | The platform's scanner failed after it accepted the request. A wrong organisation slug in `webhook-url` is refused with HTTP 401 instead (below) |
| Code analysis reported as `no_files` | `send-file-contents` is off, the payload went over 2 MB, or every changed file was binary or over a size cap (the scanner's is 512,000 bytes); only secrets were scanned |
| Code analysis reported as `not_configured` | The Valystrum instance has no SAST sidecar deployed; only secrets are scanned. When files were sent the job warns, and `fail-on-error: true` fails it |
| Code analysis reported as `timeout` or `error`, files sent | Opengrep and Trivy run side by side with 20 seconds each, and the platform stops waiting at 25 seconds, so a large change set or a busy scanner reports `timeout`. The warning and the summary name the checks that ran (`scanned.checks`), and `fail-on-error: true` fails the job |
| HTTP 401 `Invalid signature: sign with this repository's CI key (POST /pipeline/config creates one).` | One answer for each of these, so it tells nobody which organisations exist or which repositories have a key. The secret in `CS_WEBHOOK_SECRET` is wrong or rotated, or the workflow uses a release before v1.1, which sends the refused `sha256=` form. The organisation slug in `webhook-url` is wrong: copy the URL from **Settings → CI pipeline keys**. Or no active key matches this repository (the organisation-wide key is retired: see **Managing keys** to move off it): step 1 may never have been run for it, or the key may have been revoked. The repository may also have been renamed or transferred, or typed differently in step 1: the key must name `owner/name` exactly as `$GITHUB_REPOSITORY` does, case included. Rebind a renamed repository without rotating its secret: `PATCH /api/v1/<org>/pipeline/config/<keyId>` with `{"repo": "owner/new-name"}`. If the new name ever had a key of its own, revoked or not, the rebind fails: issue a key for the new name in step 1 instead and put its secret in `CS_WEBHOOK_SECRET`. Findings stay under the name they were raised with: after a rename or transfer, the new name's scans raise what they find as new findings, a finding you accepted or marked a false positive under the old name included, and no scan of the new name closes a finding of the old name or asks for the rotation of one of its secrets. The **Dev Pipeline** module keeps listing the old name with its open findings, and you resolve them in **Findings** |
| HTTP 401 `Signature timestamp outside the five-minute window` | The runner's clock is off by more than five minutes; the signature is stamped with `date +%s` |
| HTTP 401 `Signature already used` | The same signed request was sent twice; each attempt, retries included, signs afresh, so this only happens on a manual replay |
| HTTP 403 `FeatureLocked` | The organisation is below Gold; pipeline security is a Gold capability |
| HTTP 413 | The request is over 2 MB even without file contents (the diff travels base64-encoded, so about 1.5 MB of raw diff); narrow it with `paths` |
| HTTP 429 | More than 60 scans a minute for the organisation, counted only once a request's signature checks out, or more than 300 requests a minute from one address, signed or not (runners behind one NAT share an address). The action retries (see Known issues) |

**Known issues.** The action tries up to three times when there is no answer or the answer is 408,
429 or a 5xx, waiting up to 120 seconds for each attempt. A retry after a timeout or a 5xx that came
after the platform had started the scan runs it a second time, and you see two scans for one
commit. Two scans of the repository that reach the same finding within the same few milliseconds can overwrite
each other's branch record, so a finding can close while another branch still has it, or stay open; that branch's
next scan that reads the file records it again.

## Releases and pinning

Each release is a tag of this repository, listed in [CHANGELOG.md](CHANGELOG.md), and `@v1` moves to the newest v1
release. Pin by commit SHA rather than `@v1` if you need the action itself (what it sends and how it reads the
answer) to stay the same across runs. The rule set lives on the Valystrum side and changes when Valystrum moves its pin
and rebuilds the scanner image: pinning this action does not pin the rules.

The action signs `"<unix seconds>.<body>"` with HMAC-SHA256 and sends `X-CS-Signature: t=<seconds>,v1=<hex>`; the
platform accepts a stamp within five minutes, once, so every attempt, retries included, is signed afresh. The earlier
`sha256=<hex>` form (body only, no stamp) has been refused with HTTP 401 `Invalid signature` since 2026-09-28, so a
workflow pinned by commit SHA to a release before v1.1 fails: use `@v1`.

### Upgrading from v1.1

A workflow pinned to v1.1 (its tag or its commit SHA) still works against Valystrum, with these differences:

- `fail-on-error: true` fails the job only on a non-200 answer. An answer carrying `error` reads as a clean pass with
  no warning, and an answer that is not JSON (a proxy's error page) fails the job whatever `fail-on-error` says.
- Its job summary says "Scanned the diff for secrets and IaC" on every scan whose code analysis did not finish, and it
  neither warns nor reads which checks ran (`scanned.checks`).
- It sends none of `sequence`, `committedAt` and `defaultBranch`. Valystrum then orders a branch's scans by when each
  request arrives, so an older push whose request arrives last counts as the newer scan, and no branch decides over
  another: a finding stays open while any branch's latest scan still finds it, and closes only when no branch that
  read its file still does. A finding recorded before Valystrum v0.21.0 that no scan has found since is never closed by
  a v1.1 scan: resolve those in Valystrum, or move to v1.2.
- When a branch moves from v1.1 to v1.2, its scans are compared by time until both scans in a comparison carry a run
  id: a v1.1 scan by when its request arrived, a v1.2 scan by its commit's time. A commit made before the branch's last
  v1.1 scan arrived (pushed later, say) counts as the older scan and decides nothing for the files that scan read; the
  branch's next scan of a newer commit decides them.
- A clone that holds only the commit built and cannot fetch its history fails the job with a git error, where v1.2
  reports `No changes to scan`.
