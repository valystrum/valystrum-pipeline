# Valystrum Security Pipeline Action

Scans a pull request for **leaked secrets**, **code vulnerabilities (SAST)** and **IaC
misconfiguration**, and blocks the merge on critical/high findings. Results appear inline on the
PR's Files tab, in the job summary, as a PR comment, and in Valystrum under
**Validate → Developer Pipeline**.

Same shape as [`valystrum/sbom-action`](https://github.com/valystrum/sbom-action): one step, one
repository secret, HMAC-signed.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0   # the scan diffs against the base branch

- uses: valystrum/pipeline-action@v1
  with:
    webhook-url: https://app.valystrum.io/api/v1/<org>/pipeline/scan
    webhook-secret: ${{ secrets.CS_WEBHOOK_SECRET }}
```

## What actually runs

Three engines, one findings list. Each finding carries a `kind`, a rule id, `file:line`, a
remediation hint and a CWE where the rule has one.

| Kind | Engine | Covers |
|---|---|---|
| `sast` | Semgrep, ~1,200 rules from the official registry (`p/default`, `p/terraform`, `p/kubernetes`, `p/dockerfile`, `p/secrets`) | JS/TS, Python, Java, Go, Ruby, PHP, C#, Terraform, Kubernetes, Dockerfile |
| `secret` | Valystrum's secret scanner over the diff's added lines | AWS keys, GitHub/Slack tokens, Stripe live keys, private keys, Google API keys, JWTs, generic API keys |
| `iac` | Built-in Terraform/Helm rules | Fallback when file contents are not sent |

The rules are **not** maintained by you: they come from Semgrep's registry, pinned into the
platform's scanner image and updated when that image is rebuilt.

**SAST needs file contents.** Semgrep parses whole files, and a unified diff carries only hunks, so
this action sends the changed files alongside the diff (`send-file-contents`, on by default). With
it off — or on an older version of this action — the platform still scans secrets and IaC and tells
you code analysis was skipped rather than reporting a silent zero.

## Setup

**1. Get the CI secret** (once per repository — if you already run the SBOM action for this repo,
you have it and can skip to step 2):

```bash
curl -X POST https://app.valystrum.io/api/v1/<org>/pipeline/config \
  -H "content-type: application/json" -d '{"repo": "acme/web-api"}'
```

The response contains `webhookSecret` (`cs_wh_…`), shown **once**. Re-running does not rotate it
unless you pass `{"repo": "acme/web-api", "regenerateSecret": true}`.

**2. Add it as a repository secret** — `Settings → Secrets and variables → Actions` — named
`CS_WEBHOOK_SECRET`.

**3. Copy [`examples/security-scan.yml`](examples/security-scan.yml)** to
`.github/workflows/security-scan.yml` and replace `acme` in the `webhook-url` with your org slug.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `webhook-url` | yes | — | `https://app.valystrum.io/api/v1/<org>/pipeline/scan` |
| `webhook-secret` | yes | — | Repository CI secret (`cs_wh_…`) |
| `base-ref` | no | PR base SHA | Ref to diff against |
| `paths` | no | — | Space-separated pathspecs to limit the diff, e.g. `infra/ app/` |
| `send-file-contents` | no | `true` | Send changed files so SAST can run |
| `fail-on-findings` | no | `true` | Fail the job when the scan reports `passed=false` |
| `fail-on-error` | no | `false` | Fail the job when the scan endpoint is unreachable |
| `github-token` | no | — | Lets Valystrum post findings as a PR comment |

## Outputs

| Output | Description |
|---|---|
| `passed` | `'true'` when no critical/high finding was reported |
| `findings` | Number of findings |
| `scan-id` | Valystrum scan id |

## What blocks a merge

`passed` is `false` when **any critical or high** finding is present, of any kind, and the job then
fails (`fail-on-findings: true`). Semgrep severities map to Valystrum's four levels — ERROR→high,
WARNING/MEDIUM→medium, INFO→low — with directly exploitable weakness classes
(CWE-78/89/94/95/502/798/918: command and SQL injection, code injection, unsafe deserialization,
hardcoded credentials, SSRF) raised to **critical**.

**A scanner outage never blocks you.** The endpoint always answers HTTP 200, and an unreachable
endpoint is treated as a pass unless you set `fail-on-error: true`.

## Secrets are never echoed

A detected credential is reported as a masked preview (`AKIA••••3456`) — never the raw value.
Findings are printed into job logs and public PR comments, so the raw secret is redacted before it
ever leaves the platform. Detections also land in **Data Security → Secrets** in Valystrum, scoped
to this repository, so the same key leaked in two repos stays two findings.

## Size limits

The signed body is capped at 2 MB. File contents are capped at **300 files, 512 KB each**, with the
largest dropped first; if the payload still exceeds the cap the action retries without file
contents (secrets + IaC still run). Narrow the scan with `paths` on very large PRs.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No changes to scan` | The diff is empty — usually a depth-1 checkout with no base commit. Set `fetch-depth: 0` on `actions/checkout` |
| Code analysis reported as `no_files` | `send-file-contents` is off, or every changed file was binary/oversized |
| Code analysis reported as `not_configured` | The Valystrum instance has no SAST sidecar deployed; secrets + IaC still run |
| HTTP 401 `Pipeline not configured` | Step 1 was never run for this repo (or the org-wide fallback) |
| HTTP 401 `Invalid signature` | Wrong or rotated secret in `CS_WEBHOOK_SECRET` |
| HTTP 413 | Diff over 2 MB — narrow it with `paths` |

## Pinning

Pin by commit SHA rather than `@v1` if you need the scan behaviour to be byte-stable across runs.
Note the rule set lives on the Valystrum side and updates when that image is rebuilt — pinning this
action does not pin the rules.
