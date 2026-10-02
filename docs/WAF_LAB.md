# WAF Lab

The WAF lab is a bounded, plan-first workflow for **authorized** Cloudflare WAF
testing. It is separate from `cf_waf_tester.py`: there is no fallback to that
CLI's DDoS, bypass, browser, or high-volume functionality.

Use only systems you own or have explicit written authorization to test.
Low-impact probes are **not harmless on vulnerable applications**. A probe
that reaches an existing origin can trigger application side effects, alerts,
challenges, logging, or costs. Prefer an isolated, inert lab origin/route and
review every planned path, header, query, and body before approving. Existing
authorized origins are allowed; the lab does not require newly provisioned hosts.

## Project Setup

The project ships these OpenCode files:

- `.opencode/agents/waf-lab.md`: a selectable, restricted primary agent.
- `.opencode/tools/waf_lab.ts`: eight fixed custom tool operations.
- `.opencode/package.json`: pinned plugin SDK and local typechecking dependencies.
- `.opencode/tsconfig.json`: strict, no-emit TypeScript checking.
- `.opencode/tests/waf_lab.test.ts`: offline SDK/tool tests running a fake CLI in real subprocesses.

The Python prerequisite is `waf_lab.py` at the worktree root, implementing the
CLI contract below, with its Python dependencies installed. The adapter fails
closed if that entry point is missing. It does not create Python modules, install
Python dependencies, provision hosts, or send probes during installation.

The guarded transport requires `aiohttp==3.13.3` from `requirements.txt`. Its
implicit disconnected-GET retry is disabled so one planned request cannot
silently send twice. Reinstall the requirements if an older environment is used.
Node 24 or newer is recommended for the adapter's native TypeScript test runner.

From the project root, install/check the local adapter dependencies:

```bash
npm --prefix .opencode install --ignore-scripts --package-lock=false
npm --prefix .opencode run check
npm --prefix .opencode test
```

The SDK is pinned in `.opencode/package.json`. Use an OpenCode release
supporting `ToolContext.worktree`, `abort`, and `ask`; the adapter was built
against that SDK, not an assumed approval API. Bun is not required for the local
TypeScript check; the adapter uses Node-compatible `child_process.spawn`, not
`Bun.$` or a shell command string.

Tests use Node's built-in runner and native TypeScript stripping (Node 22.18+
or a current newer release). Most create isolated fake worktrees beneath
`.opencode`, run a JavaScript fixture named `waf_lab.py` with `process.execPath`
as `CF_LAB_PYTHON`, and clean up afterward. They exercise real SDK tools and
subprocess boundaries. A separate real Python planning/review roundtrip uses
mocked inventory, DNS and TLS metadata with sockets blocked. Neither sends target
traffic or calls external APIs.
Coverage includes target/budget guards, worktree/session scope, exact request-review
delivery, full approval metadata and ordering, rejection/tampering, injection,
cancellation and output limits, redirect policy/request validation, fixed review
and report pagination argv/bounds, and no traffic replay after analysis overflow.
No additional test framework or installation is needed.

**Quit and restart OpenCode** after installing/changing the agent or tools. Start
OpenCode from this worktree and select `waf-lab` as the primary agent. No global
config, default-agent change, MCP server, or static initial host allowlist is
required. The custom tools reject calls from other agents. Name the exact hosts
and chosen base paths conversationally for each new run; accessible zones and
previous runs are not authorization or an expanded scope.

Interpreter selection is `CF_LAB_PYTHON`, then an executable
`<worktree>/venv/bin/python`, then `python3` on `PATH`. `CF_LAB_PYTHON` must name
one executable, preferably an absolute path, not a command with arguments.
The script path and subprocess working directory come from `context.worktree`,
not the OpenCode process's current directory. There is no legacy CLI fallback.

## Restricted Permissions

The agent's permission rules are ordered broad-first, with the last matching
rule winning:

```yaml
permission:
  "*": deny
  "waf_lab_*": allow
  waf_lab_execute: ask
  question: allow
```

Only these eight fixed tools and `question` are permitted:

| Tool | Operation |
| --- | --- |
| `waf_lab_catalog` | Fixed catalogue and profiles |
| `waf_lab_inventory` | Read-only host-scoped Cloudflare inventory |
| `waf_lab_plan` | Prepare a saved, digest-bound plan without target traffic |
| `waf_lab_review` | Exact, bounded request-review pages for this session's plan |
| `waf_lab_execute` | Single-use execution after complete review and fresh permission |
| `waf_lab_report` | Saved summary or bounded evidence pages |
| `waf_lab_correlate` | Read-only event correlation, without probe replay |
| `waf_lab_compare` | Compatible saved schema-2 run comparison |

Shell/bash, edits, file reads/searches, arbitrary network requests, task/subagent delegation,
webfetch, skills, MCP tools, and portal code execution are denied. Inventory and
event correlation go through a fixed, read-only Python API client, not a broad
MCP portal executor. These restrictions apply to the selected `waf-lab` agent;
they do not sandbox other agents or a human terminal, or protect against a
maliciously modified local CLI/plugin. Keep the project code trusted.

**Do not enable auto-approve**, use `opencode --auto`/`opencode run --auto`, set
session permission overrides that allow execution, or choose "always". These
modes can defeat human approval despite a tool calling `context.ask`. Keep
execution set to `ask` and choose **once** or **reject** for each run. Do not
change global configuration to make this workflow work.

## Plan And Approve

1. Supply the exact hosts and inert base paths, confirm ownership/written
   authorization, and choose profiles/budgets for this run. Targets can be DNS
   hostnames or HTTPS URLs on port 443 with a safe literal base path;
   hostname/path shorthand is also accepted. For example,
   `https://LAB.example.com:443/Inert/Probe/` normalizes to
   `https://lab.example.com/Inert/Probe/`. Only the host is lowercased; path case
   and trailing slashes are preserved. Use punycode for IDNs. Reject credentials
   (even an empty `@`), queries/fragments (even bare `?`/`#`), IPs, wildcards,
   whitespace, non-ASCII, backslashes, encodings and `.`/`..` path segments.
   Literal paths start with `/` and contain only ASCII letters, digits,
   `/`, `_`, `.`, `~` and `-`. Choosing a base path routes the fixed catalogue;
   it does not expose a generic HTTP-request or arbitrary-payload API. Prepare those
   routes to be inert; some catalogue cases append fixed child paths beneath
   the base path, so review every rendered request, not just the base route.
2. Inspect the catalogue and optionally read Cloudflare inventory. Planning can
   resolve DNS and read inventory but sends no probe traffic to the target.
3. Create a plan. Its JSON includes `plan_id`, `approval_digest`, `cases` (the
   full request list), `budgets`, `targets`, `profiles`, `catalogue_version`,
   `created_at`, `dns_pins`, `inventory` (summary), `warnings`, `tls_policy`,
   `redirect_policy`, `redirect_requests` (complete conditional requests), and
   `maximum_sends` (worst-case sends). `request_count` counts original cases;
   `concurrency: 1` and `follow_redirects: false` remain required. Raw rulesets
   are not embedded in the displayed plan: the full snapshot is saved privately
   as `inventory.json` and bound to approval by its digest. Approval `plan` and
   `show` still return the full plan with ALL original and conditional request
   entries, at most 500 combined. They are not paginated, but do not satisfy the
   separate exact request-review gate. Report `plan` pages cannot replace it.
4. Review the **complete** plan and call `waf_lab_review` until ALL original and
   conditional request indices have been delivered in this same session. Display
   each `review_text` **verbatim in a literal fenced block**, including page
   boundaries, request indices and end markers. Preserve each complete request
   JSON object: full URL and every query character, ALL headers, and the entire
   body, including multipart boundaries, parts, filenames and escaped CRLFs.
   No abbreviated URLs, multipart/body summaries, ellipses, placeholders or
   selected-field excerpts count as review. Original cases explicitly print
   `Host`, `Connection: close`, and, for non-null bodies, `Content-Length` equal
   to the UTF-8 byte length. Conditional redirects print their derived `Host`
   and fixed `Connection: close`; their body is null. Also display the exact
   ID/digest, targets/base paths, redirect destination routes, profiles, every
   budget field, original/conditional entry counts, `maximum_sends`, TLS/redirect
   policies, DNS pins, warnings and application risk. Do not execute if any
   output is truncated, any index is missing, or the plan cannot be inspected.
5. `waf_lab_execute` calls `show`, validates the stored ID/digest and bounded
   plan, and compares the complete plan against the worktree/session's prepared
   snapshot. A changed plan is rejected before prompting or spawning `run`,
   even if its displayed digest has not changed. Missing review indices are
   rejected before any permission prompt. With ALL indices delivered, it calls
   `context.ask` with `permission: "waf_lab_execute"`,
   `patterns: ["<plan_id> <approval_digest>"]`, and `always: []`. Permission
   metadata includes the complete displayed plan, exact review text, targets,
   profiles, budgets, request counts, `maximum_sends`, redirect policy, risk and
   session ID. The unchanged plan is checked again after permission and before
   `run`. Each execution requires this tool-level request; there is no
   model-supplied approval boolean or chat-consent substitute.
6. Approve once or reject. Only after approval does the adapter invoke
   `run --plan-id <UUID> --approve <digest>`. The CLI must validate the digest
   against the saved plan before sending traffic. Changing the experiment
   requires a new plan, complete review and fresh approval, not editing approval
   arguments. This includes changed TLS trust, redirect policy/destinations,
   conditional requests or DNS pins. Plans expire after one hour and are single-use.
7. Execution persists the complete report and returns a compact summary. Read
   the report summary/pages, explicitly call `waf_lab_correlate` to fetch provider
   events, and optionally compare a baseline. `run` does **not** automatically
   fetch or correlate live Cloudflare events; its initial report contains response
   observations and unavailable/unmatched evidence. Correlation updates the
   saved report and returns a summary without replaying probes or modifying
   Cloudflare configuration.

Session binding is in memory: the adapter keys plans by worktree, OpenCode
`sessionID`, and plan ID without adding unsupported CLI session flags. An
approved plan is consumed before spawning, including on subsequent failure;
concurrent calls cannot spend it twice. Rejection does not consume the plan,
but any later attempt still needs a fresh permission request. Do not retry
execution automatically. A new session or OpenCode restart needs a newly
created/reviewed plan; existing report IDs remain usable for analysis.

## Exact Request Review

`waf_lab_review` requires `plan_id` and `approval_digest`; optional `offset` and
`limit` default to 0 and 5. Offset is a nonnegative integer, limit is 1-5, and an
offset outside the request list is rejected. The CLI uses fixed argv:

```text
review --plan-id <UUID> --offset <offset> --limit <limit>
```

Each page is one complete JSON value with `{plan_id, approval_digest, offset,
limit, total, items, more, review_text}`. Entries are `cases` followed by
`redirect_requests`; offsets are zero-based, while the visible `REQUEST N OF T`
markers are one-based. `review_text` starts with `BEGIN EXACT REQUEST REVIEW`
and the full plan ID/digest, contains indented exact request JSON between each
request's markers, and finishes with `END EXACT REQUEST REVIEW N OF T`.

The complete CLI stdout page, including JSON escaping and its newline, is capped
at **12000 bytes**. An oversized page fails; reduce `limit`, never shorten its
contents. Planning verifies that each individual request can fit a limit-1 page.
The adapter validates the unchanged full plan before and after review, checks
page items against the exact saved request dictionaries, and parses the complete
JSON objects inside `review_text` to check equality before recording indices.
Partial, changed, invalid or oversized results do not satisfy the review gate.

Advance `offset` by the returned item count until every index in `total` has been
delivered. `more: false` alone does not establish that earlier pages were shown.
Full `plan`/`show` output, ordinary report pages, or chat summaries do not record
approval-review indices. The tool tracks delivery, not human comprehension: the
agent must still display the exact text, and the user must inspect it before
approving once or rejecting the fresh execution permission prompt.

## Budgets And Profiles

| Setting | Default | Bound |
| --- | --- | --- |
| Hosts | Supplied conversationally each run | 1-10 |
| Profiles | `sqli`, `xss` | Fixed enum below |
| Total requests | 100 | 1-500, including controls, redirects and all hosts |
| Requests/second | 1 | Finite, 0.1-2 |
| Runtime seconds | 180 | 1-600 |
| Request timeout seconds | 10 | 1-30 |
| Concurrency | 1 | Fixed at 1 |
| Target transport | HTTPS | Port 443 only |
| DNS pins | Public addresses only | First approved IP per host, no fallback |
| Redirects | Disabled | Explicit exact routes only; manual GET/HEAD handling, 1-3 hops |
| Review entries | All original and conditional requests | At most 500 combined |

Request timeout cannot exceed the runtime budget. The runner also rejects a
plan whose complete request schedule cannot fit the chosen rate/runtime.

Available profiles are `smoke`, `sqli`, `xss`, `command`, `traversal`, `ssti`,
`ldap`, `xxe`, `ssrf`, `prototype`, `log4j`, `scanner`, `managed`, and `all`.
Their names label fixed catalogue families, not proof that real exploits work.
Controls count toward the request budget. Larger selections, multiple hosts,
and `all` may need a larger **explicit per-plan** budget; review the catalogue
and plan rather than assuming the default 100 can cover everything. Do not
silently increase limits or interpret `all` as all Cloudflare rule coverage.

The Python runtime enforces public-DNS pinning, HTTPS/443, transport-level
redirects off, strict TLS, single concurrency and traffic budgets. Explicit
manual redirects are subject to the separate policy below. The adapter independently
validates bounded numeric inputs/plans and exposes no raw request, arbitrary payload,
Cloudflare API endpoint override, API mutation, or arbitrary subprocess operation.
Cloudflare inventory/event API requests are separate from the target-probe
budget, with bounded discovery/query behavior in the fixed API client.

Each subprocess has a 660-second adapter deadline (separate from the plan's
target runtime). Cancellation, deadline expiry, or output overflow sends TERM,
then KILL after two seconds if needed, with a final one-second pipe cleanup
deadline. Captured stdout is capped at 4 MiB except for the 12000-byte review
cap; stderr is capped at 64 KiB. Overflow fails the operation, not a silently
successful truncated result. An abort may
leave completed attempts: read the saved report before planning another run.
OpenCode may apply a smaller display limit; incomplete visible evidence is not
an executable-plan review or a complete report. An analysis output overflow is
NOT a reason to retry execution or generate another traffic run. Use smaller
report pages or state the evidence limitation; keep the 4 MiB output cap.

## Target TLS

The target transport deterministically selects `dns_pins[hostname][0]`, the
first approved address in the saved list (planning sorts public DNS results).
It does not try another pinned IP on failure, re-resolve at send time, rewrite
the URL to an IP, or silently rerequest after a disconnect. Each send uses a
new connection (`force_close: true`), no proxy (`proxy=None`, `trust_env: false`),
no response-cookie persistence (`DummyCookieJar`), and no automatic HTTP retry.
Explicit catalogue Cookie headers remain part of the original reviewed request;
they are not cookies collected from an earlier response.

The original hostname URL and exact encoded path/query are preserved. TLS SNI
and certificate hostname validation use that hostname, not the pinned IP.
Any supplied `Host` must match it (case-insensitive, optionally `:443`); mismatches
fail before connecting. A matching header is removed internally so aiohttp
derives the wire `Host` from the unchanged URL. TLS remains `CERT_REQUIRED` with
`check_hostname: true`; this Python runtime's default verification flags, protocol
bounds and ciphers are retained. There is no insecure mode, lowered verification,
alternate-IP/trust-store fallback, proxy-environment routing or hidden replay.

`modules/lab_tls.py` eagerly snapshots the effective OpenSSL CA file and every
certificate file with a hash name such as `01234567.0` in the effective CA
directories, including all configured directory components. `SSL_CERT_FILE` and
`SSL_CERT_DIR`, when present, select those default sources. The final memory-only
SSL context loads the snapshot through `cadata`, with no lazy file/directory
lookups during TLS handshakes. Unreadable, malformed or unsupported configured
sources fail closed; an absent compiled default contributes no trust, and the
combined snapshot must contain at least one CA. Unsupported native stores,
trusted-PEM/X509_AUX semantics and hashed CRLs are not silently discarded or
replaced. A nonempty `SSLKEYLOGFILE` is rejected before a key-log file is opened.

The saved `tls_policy` includes runtime versions, trust-source name, environment
override **names only**, loaded certificate counts, verification settings,
`trust_snapshot_frozen: true`, and `ca_fingerprint`. The fingerprint is SHA-256
of the concatenation of byte-sorted, unique DER certificates in the **entire**
trust snapshot, including non-CA certificates, not just `get_ca_certs()` output
or a bundle path. Duplicate certificates, PEM ordering and comments do not
change it; changed certificate material does, even if CA counts match.
`ca_counts_scope` is `loaded_certificates_only` and `ca_fingerprint_scope` is
`all_trust_der_certificates`.

The complete TLS policy is digest-bound at planning, recomputed at run preflight,
and compared again before the transport creates its connector/session. A change
requires a new plan, exact review and fresh permission. The transport then uses
the exact frozen context it compared; later source-file changes cannot alter
that in-memory context or trigger fallback loading.

### Explicit Target Trust

`CF_LAB_CA_BUNDLE` is an explicit, separately approved choice of a **complete PEM
trust bundle for lab targets only**. The authorized human supplies it through the
OpenCode process environment before planning, never through chat, tool arguments,
committed configuration or an automatic agent repair. It **replaces**, rather
than supplements, all default target trust sources. Include the complete trust
set intended for this experiment; it is not an instruction to append a site's
certificate or discover/add a CA after an error. The agent must not change trust
or weaken verification to make a failed control pass.

The bundle must be a readable regular ASCII PEM certificate file with at least
one CA. Multiple certificates and `#` comment lines are supported; an empty
setting, empty/malformed bundle, trailing junk, truncated/unsupported PEM or a
bundle without a CA fails closed with no default fallback. Metadata records
`trust_source: "CF_LAB_CA_BUNDLE"` and that environment variable's name, not its
value or source path. Verification flags and hostname checks remain unchanged.
This setting does **not** configure Cloudflare API reads: that separate client
still uses verified `httpx`/certifi trust with `trust_env: false` and
`follow_redirects: false`.

### Diagnostics And Saved Failures

New attempt pages include `connection_diagnostics`: requested hostname, selected
pinned IP, SNI/server hostname, derived Host, pin policy, proxy/environment/close/
retry/redirect settings, and TLS metadata. Certificate-verification failures can
also include `certificate_verification` with a numeric `verify_code` and a fixed,
sanitized `verify_message`; arbitrary exception text, CA source paths and
environment values are not saved. Unknown codes produce the generic
`certificate verification failed` message. Diagnostics describe the local
verification attempt, not a universal judgment about a site's certificate.

The following existing schema-2 plans, reports and saved attempt records were
inspected on 2026-09-30, without replaying requests:

| Saved Run ID | Attempts | Attack Probes | Result |
| --- | --- | --- | --- |
| `677d1a17-08a2-4be0-9732-7850237c2d4d` | 1 benign control | 0 | `stopped_controls` |
| `c8007192-9200-45da-b410-7357256288ec` | 1 benign control | 0 | `stopped_controls` |
| `3b2129d8-11f4-42f8-9f9e-e2c7c4956a73` | 1 benign control | 0 | `stopped_controls` |

Each stopped at its first `smoke-query-control` with
`ClientConnectorCertificateError`, no HTTP status and no CF-Ray. Across these
runs there were **three failed benign-control attempts and zero attack probes**;
the run with 49 planned cases still sent only its first control. These older attempts
do not contain the new structured verification code/message or TLS trust
snapshot. The actual issuer/verification reason is unknown: do not call the
site certificate bad, infer a missing issuer, or claim these changes diagnosed
or repaired those failures. They establish no WAF enforcement or bypass result.

Local, no-network runtime checks on that date found the default `curl` at 8.7.1
with LibreSSL 3.3.6 (its version output also lists SecureTransport), versus the
project Python at 3.13.13 with OpenSSL 3.6.2. Python's effective default, compiled
CA file and certifi contexts loaded different certificate sets. The exact trust
material curl used for the reported successful request was not captured, so it
must not be assumed identical to or different from the lab's historical trust.
`SSL_CERT_FILE` was present in the Python environment; only its **name** is
recorded here, never its value. These machine facts are not the historical
failure's diagnosis, and a result from another client cannot prove this lab
transport would pass.

**No live verification of the TLS/redirect changes was performed for this
documentation update.** Offline tests or saved-report reads are not a new control
result. Any fresh benign control, TLS connection or attack probe requires fresh
host/route authorization, a new plan, complete exact review and a new once-only
execution permission. Never automatically replay an old run to verify a fix.

## Redirect Policy

Redirects default to this complete saved policy:

```json
{"enabled": false, "max_hops": 0, "destinations": []}
```

For a HEAD-only benign connectivity experiment, explicitly choose
`profiles: ["smoke"]` and `smoke_method: "HEAD"` when planning. The default
`smoke_method` is `GET`; `HEAD` is permitted only when `smoke` or `all` includes
that benign control, and never converts POST signature fixtures into GET/HEAD.
The method is saved in the plan and bound to approval, including every
conditional redirect request.

Omit `redirect_policy` unless the user explicitly requests redirects and
authorizes **each exact destination route for this run**, including same-host
routes. An enabled policy has only these fields, for example:

```json
{
  "enabled": true,
  "max_hops": 1,
  "destinations": ["https://redirect.example.com/Inert/Next/"]
}
```

`enabled` is boolean, `max_hops` is an integer 0-3, and `destinations` contains at
most 10 safe literal HTTPS/443 URLs. Enabled policies require 1-3 hops and at
least one destination; disabled policies require zero hops and no destinations.
Destination normalization lowercases only hosts, removes explicit `:443`,
preserves path case/trailing slashes, and deduplicates exact routes. No credentials,
queries/fragments (even empty), encodings, wildcards, IP targets, backslashes or
dot segments are allowed. Original and destination hosts together must fit the
10-host cap; every host gets public DNS pins and read-only inventory. Routes are
exact matches, not prefix/subtree permissions. A Location header, same-host
relationship, prior run or inventory cannot expand authorization.

`follow_redirects: false` and per-request `allow_redirects: false` always remain
in force. The runner manually considers only 301/302/303/307/308, and only an
already-reviewed GET/HEAD with a null body may follow. **POST never follows,
including 303**, and no body is replayed. A Location may be an absolute literal
HTTPS URL or a root-relative path on the current hostname; protocol-relative
URLs, path-relative references, query/fragment redirects, loops, malformed or
oversized Locations (over 4096 characters), and unapproved exact destinations
are rejected. The normalized destination must select an identical saved
conditional request within the approved hop bound.

Planning renders every eligible source-case/destination combination into
`redirect_requests`. These requests retain only `User-Agent`, `Accept`,
`Accept-Encoding` and `X-CF-Tester-Probe` from the source; `Host` is derived from
the destination and `Connection` is fixed to `close`. Cookies, Authorization,
Proxy-Authorization, API keys, Referer and all other headers are stripped on
**every** redirect, including same-host redirects. Source queries and payload
bodies are not carried to the destination; review the actual conditional JSON,
not an assumed resend of the original probe. An allowlisted probe header can
remain in a conditional request and must still be reviewed.

The review count is `len(cases) + len(redirect_requests)`, at most 500. The
worst-case physical-send budget is distinct:

```text
maximum_sends = len(cases) + eligible_body_null_GET_HEAD_count * max_hops
```

Every actual hop consumes the shared total-request, rate and runtime budgets.
The request timeout applies to the entire chain, including rate waits, and is
not reset per hop. Planning rejects an experiment whose worst-case sends exceed
the explicit request budget or cannot fit the rate/runtime schedule. The runner
never raises those budgets automatically.

Redirect delivery still requires valid CF-Ray routing evidence and no challenge,
block or transport error. A probe can follow only after its own paired control
chain has passed at that exact destination route for that original target;
another case's control, another original base path or another host is not enough.
A failed control or blocked redirect stops subsequent probes for the affected
original route. Missing routing evidence remains inconclusive, not permission
to follow or broaden the policy.

Attempt pages retain `source_case_id`, `redirect_hop` for conditional sends and
structured `redirect` status/reason/destination diagnostics. Raw Location values
are not persisted or copied into stored response headers; diagnostics retain a
SHA-256 `location_digest` and, when applicable, the normalized approved route.
Response bodies and cookies remain unsaved.

## Report Pages

`waf_lab_execute`, `waf_lab_correlate`, and the default `waf_lab_report` return
a compact summary, not the entire stored report. The summary contains:

```text
schema_version, kind, run_id, status, summary, coverage_counts,
configuration_fingerprint, telemetry_summary, warnings, warning_count, limitations
```

`waf_lab_report` accepts `plan_id` plus optional `section`, `offset`, and `limit`.
Defaults are `section: "summary"`, `offset: 0`, `limit: 20`; offset must be a
finite nonnegative integer and limit an integer from 1 through 50. The adapter
always invokes fixed argv:

```text
report --plan-id <UUID> --section <section> --offset <offset> --limit <limit>
```

| Section | Output |
| --- | --- |
| `summary` | Compact run summary, including warnings and limitations |
| `attempts` | Full request/evidence and any saved connection/redirect diagnostics |
| `rules` | Compact per-host rule-coverage ledger rows |
| `plan` | Original `cases` only, not conditional requests or the complete approval plan |
| `inventory` | Flattened host/rule metadata from captured inventory, not raw rulesets |

Non-summary pages return `{section, offset, limit, total, items, more}`. Inspect
`more` and `total`, advance the offset by the number of returned items, and keep
reading the relevant pages as needed. Do not interpret an uninspected page as
tested coverage or a complete analysis. If a page is still too large or the UI
truncates it, reduce `limit`; never rerun live traffic to obtain smaller output.

The complete schema-2 report and raw inventory snapshot remain private local
files in `reports/waf-lab/<plan_id>/`, including `report.json` and
`inventory.json`. The digest-bound raw snapshot preserves full rulesets,
ordering, overrides, expressions and versions for the runner's evidence logic.
It is not copied into approval prompts or compact inventory pages. The agent
has no arbitrary raw-file read or snapshot-dump tool; do not bypass that
restriction with shell, another agent, or MCP. Treat these files and paged
evidence as sensitive data, even when output is compact.

## Cloudflare Credentials

The direct API client reads `CF_API_TOKEN`, falling back to
`CLOUDFLARE_API_TOKEN` when the first is absent/empty. Provide the credential
through the environment of the OpenCode process, not chat, tool arguments,
agent config, plan JSON, or committed files. The adapter inherits that
environment only for the local CLI and never logs/dumps environment variables.
An existing MCP OAuth login/token is **not automatically reused**.

Use a **read-only**, resource-scoped token for the authorized zones/accounts:

- Zones Read and DNS Read for zone discovery and DNS/proxy inventory.
- WAF/rulesets Read for zone entrypoints, deployed rulesets and raw rule settings.
- Account rulesets Read if available/needed for account entrypoints.
- The available Analytics/Security Events read permissions and dataset access
  for event correlation. Names, dataset availability, sampling, retention and
  entitlements vary; an API token alone does not guarantee access.

No write/edit permissions are needed. The client uses fixed Cloudflare REST
discovery and a fixed firewall-events GraphQL query; the agent cannot supply an
API URL, token, arbitrary query, or mutation. TLS verification and redirects-off
behavior apply to API reads as well. Missing/denied evidence is reported as a
limitation, not an invitation to grant broad portal access or claim a pass.

Planning keeps the full inventory in a private `inventory.json` snapshot and
binds its fingerprint into the approval digest; the displayed plan contains
only an inventory summary. Discovery above 4 MB is rejected before traffic.
Report deployment paths are shared rather than copied for every rule, and
state reads/writes use the same 64 MB ceiling. Use smaller host selections if
the preflight ledger-size guard rejects a plan.

Benign 404/405 responses with a valid CF-Ray can establish edge delivery, but
not origin acceptance. The report retains that distinction. Missing/invalid
Ray IDs, blocked/challenged controls, transport errors, and other failed
controls stop subsequent probes for that exact target route. Event collection
can be repeated without replaying traffic; previously captured matches are
retained if later sampled or unavailable collections do not reproduce them.

## Manual CLI

Manual terminal use is outside the restricted agent's permission boundary.
Only an authorized human should run the final traffic command after reviewing
the full saved plan, every exact request-review page and its exact digest.
The manual CLI does not have the adapter's session-delivery or permission gate;
it is not a way for the restricted agent to bypass either gate. These commands
are documentation, not an install-time smoke test or an automatically executed
attack run.

```bash
# Fixed catalogue only; no arguments or probe traffic.
venv/bin/python waf_lab.py catalog

# Replace this URL with this run's explicitly authorized host and inert base path.
printf '%s\n' '{"targets":["https://lab.example.com/Inert/Probe/"]}' |
  venv/bin/python waf_lab.py inventory --input -

# Prepare only: DNS/inventory reads, no probe traffic.
printf '%s\n' '{"targets":["https://lab.example.com/Inert/Probe/"],"profiles":["sqli","xss"],"max_requests":100,"rate_per_second":1,"max_runtime_seconds":180,"timeout_seconds":10}' |
  venv/bin/python waf_lab.py plan --input -

# Use the actual UUID from the preceding plan output and inspect the full plan.
venv/bin/python waf_lab.py show --plan-id '<PLAN_UUID>'

# No traffic: inspect exact original and conditional request JSON, not summaries.
venv/bin/python waf_lab.py review --plan-id '<PLAN_UUID>' --offset 0 --limit 5
# Continue with offset advanced by items returned until ALL total indices are inspected.
# If the 12000-byte page cap rejects output, reduce limit to 1-4; never abbreviate.

# TRAFFIC: only after fresh authorization and complete human review of this plan.
# The approval digest must match the full shown plan; never replay an old ID.
venv/bin/python waf_lab.py run --plan-id '<PLAN_UUID>' --approve '<EXACT_APPROVAL_DIGEST>'

# Analysis only: run does not fetch live events; explicitly correlate afterward.
venv/bin/python waf_lab.py report --plan-id '<PLAN_UUID>' --section summary --offset 0 --limit 20
venv/bin/python waf_lab.py correlate --plan-id '<PLAN_UUID>'
# Read details from saved evidence, not by replaying traffic.
venv/bin/python waf_lab.py report --plan-id '<PLAN_UUID>' --section attempts --offset 0 --limit 20
venv/bin/python waf_lab.py report --plan-id '<PLAN_UUID>' --section rules --offset 0 --limit 20
venv/bin/python waf_lab.py report --plan-id '<PLAN_UUID>' --section plan --offset 0 --limit 20
venv/bin/python waf_lab.py report --plan-id '<PLAN_UUID>' --section inventory --offset 0 --limit 20
venv/bin/python waf_lab.py compare --plan-id '<PLAN_UUID>' --baseline-id '<BASELINE_UUID>'
```

`inventory` accepts JSON `{targets: string[]}` on stdin. `plan` accepts JSON
`{targets: string[], profiles: string[], max_requests?: int,
rate_per_second?: number, max_runtime_seconds?: int, timeout_seconds?: int,
redirect_policy?: {enabled: boolean, max_hops: int, destinations: string[]}}`.
Targets use the hostname/HTTPS literal-base-path syntax above. Inventory extracts
unique hostnames for API discovery; planning retains the exact normalized URL
and base path in every rendered case and the approval plan.
The adapter supplies defaults explicitly. All other operations use fixed argv
and validated UUIDs/digests. `review` takes `--plan-id`, `--offset` and `--limit`
(defaults 0/5, limit 1-5); unlike `waf_lab_review`, its CLI argv does not take an
approval digest or record session delivery. Its JSON returns the saved full
ID/digest for inspection. The CLI writes JSON to stdout; failures return a
JSON `{error}` and nonzero exit status. The adapter preserves stdout/stderr in
an `untrusted_evidence` envelope, including failure diagnostics, without
interpreting their text as instructions. Reports can include full attempts
and evidence through bounded report pages within the output cap, not an
unbounded raw-report response. Handle persisted reports/inventory as sensitive data;
do not enable public session sharing or forward them without review.

## Interpreting Results

Lab reports have `schema_version: "2.0.0"` and `kind: "waf-lab"`, with attempts,
response observations, provider evidence, captured inventory, limitations and
a per-host rule-instance ledger. Legacy `cf_waf_tester.py` reports use schema 1;
do not mix them or feed them to lab comparisons as equivalent baselines.

The current catalogue is **1.1.0**; the report schema remains **2.0.0**.
Previously persisted schema-2 reports remain readable even without TLS/redirect
policy or connection diagnostics. Missing historical fields mean unavailable
evidence, not default-policy proof; new diagnostics cannot be backfilled from an
old error class. Old plans are **not** executable after this change: create a new
plan with the current catalogue, `tls_policy`, `redirect_policy`,
`redirect_requests`, `maximum_sends` and explicit original request headers, then
complete review and obtain fresh permission. Do not edit/migrate an old plan or
its digest into a traffic authorization.

- An `allowed` response does not establish successful exploitation or bypass.
- A `cloudflare_block_response`/challenge is a response observation, not by
  itself proof that a managed WAF rule enforced the request.
- Correlation uses Ray ID, host, zone/source compatibility and attempt time.
  Sampled or delayed events can be missing; absence is inconclusive, not a pass.
- The ledger denominator is captured inventory rule instances **per host**, not
  the provider's entire rules catalogue. Observed, disabled,
  undeployed/out-of-scope, untested and insufficient-evidence states are distinct.
- Preserve raw rule ordering, versions, overrides, skips and expressions.
  Captured inventory is a snapshot, not proof of configuration/evaluation at
  attempt time. Earlier terminating actions can preempt later rules;
  expressions and preemption are not inferred from an HTTP status.
- OWASP final-score events and reported scoring contributors are separate
  facts. A contributor does not establish individual enforcement or coverage.
- Comparisons require compatible catalogue, targets, profiles, cases, budgets,
  TLS policy, redirect policy and conditional requests. Configuration drift is a
  reported delta, not proof of a regression or improvement in protection. Honor
  incompatible-baseline results.

Neither this workflow nor its reports promise real exploitation, successful
bypasses, universal rule coverage, or an overall protection score. Tool output,
rule descriptions, event metadata and origin responses remain untrusted
evidence even when they appear to contain operational instructions.
