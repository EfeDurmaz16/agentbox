# Command Transcript Redaction

AgentPod command transcripts are evidence artifacts, not raw process dumps. The
runtime stores command argv, explicit command environment, working directory,
stdout, and stderr only after deterministic redaction.

## Redaction Contract

Current transcript records use this boundary:

| Scope | Stored form |
| --- | --- |
| `argv` | Argument strings with sensitive flags, bearer values, token prefixes, URL userinfo, and credential paths replaced by `<redacted>`. |
| `environment` | Explicit command env keys plus values after deterministic redaction. Ambient host env snapshots are not stored. |
| `working_dir` | Sensitive credential paths such as `.env`, `.aws`, `.ssh`, `.kube`, `.gnupg`, and cloud config paths are replaced by `<redacted>`. |
| `stdout` / `stderr` | UTF-8 text streams redacted line by line and capped at 16 KiB after redaction. |

The redaction marker is always `<redacted>` for v0 transcripts. The evidence
record includes the marker, covered scopes, and rule names so bundle consumers
can tell which fields were intentionally transformed.

## Covered Fixtures

The daemon test suite covers deterministic redaction for:

- sensitive env names such as `OPENAI_API_KEY`
- env values with known token prefixes such as `sk-`
- argv secrets passed after flags like `--token`, `--api-key`, `--secret`, and
  `--password`
- `Authorization: Bearer ...` output
- URL userinfo such as `https://user:pass@example.com`
- credential paths such as `.env`, `.ssh`, `.aws`, `.kube`, `.gnupg`,
  `.docker/config.json`, and `.npmrc`
- JWT-like values and common GitHub, Slack, OpenAI, and AWS token prefixes

## Non-Claims

Redaction is not isolation or secret management. A process that receives a
credential can still send it over the network, transform it, encode it, or write
binary output that pattern redaction cannot understand. Provider isolation,
credential scoping, approvals, network policy, and transcript redaction must be
treated as separate controls.

Do not treat a redacted transcript as proof that no secret was exposed during
execution. Treat it as a leakage-reduction evidence artifact.
