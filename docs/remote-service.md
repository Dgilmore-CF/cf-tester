# Remote WAF Executor Contract

This service is an idle, standalone `remote-waf` executor. It does not invoke
guarded `waf_lab` plans/tools, classic DDoS/bypass testing, WARP, or the Cloudflare
API. Reduced-impact signatures can still harm vulnerable applications. Submitting
`authorization: true` authorizes the original targets and automatic cross-host
redirect destinations. This is not exact-request review/approval mode.

## Startup

Run one process/worker. Importing `cf_tester_service` does not read keys, open state,
resolve DNS, or start traffic. ASGI lifespan requires both environment variables:

| Variable | Contract |
| --- | --- |
| `CF_TESTER_KEY_FILE` | Regular, non-symlink UTF-8 shared-key file, at most 4096 bytes. Trailing CR/LF are removed, other whitespace is retained. Effective key must contain at least 32 characters. |
| `CF_TESTER_STATE_DIR` | Private, owned directory (0700). Created if absent. State files are private regular files (0600). Must persist across restarts. |

The Docker executor runs Python 3.13 as UID/GID 10001, port 8092, one uvicorn
worker. Provision a writable private state volume and a readable mounted key
file externally. Neither is baked into the image. No deployment is included.
Only the service, runner, and fixed catalogue are copied; the eager classic
`modules/__init__.py` is deliberately omitted, creating a namespace package.

The app holds a nonblocking process lock for its entire lifespan. A competing
owner fails startup before touching run status. The owner marks previously
queued/running records `interrupted`; no run is ever replayed automatically.
Shutdown cancels the current task and persists its final status.
Cancellation captures the matching task/event before yielding; a replacement
run cannot be cancelled by an earlier run's cancellation request. A finishing
task releases active ownership only if it still owns that same run/task.

For offline integration use
`create_app(key=<UTF-8 string>, state_dir=<private Path>, runner=<injected runner>, clock=<optional UNIX clock>)`.
The runner interface is
`async run(spec, mutable_report, cancellation_event, publish_callback) -> terminal_status`.
`publish_callback()` synchronously persists current metadata; injected runners
must not add bodies, cookies, secrets, or raw Location headers to reports.

## Authentication

Every HTTP route requires these headers; no unsigned health endpoint is exposed:

| Header | Value |
| --- | --- |
| `X-CF-Tester-Timestamp` | Integer UNIX seconds, at most 60 seconds past/future drift. |
| `X-CF-Tester-Nonce` | Exactly 32 lowercase hexadecimal characters, unique per request. |
| `X-CF-Tester-Signature` | 64 hexadecimal characters containing HMAC-SHA256. |

Use the UTF-8 shared key to sign these exact bytes, without a final newline:

```text
timestamp + '\n' + nonce + '\n' + method + '\n' + path + '\n' + sha256(raw_body).hexdigest()
```

`timestamp` is the exact header string, `method` is uppercase, `path` excludes
query strings, and `raw_body` is exactly the transmitted bytes (empty bytes for
GET and cancellation). Query strings and encoded route spellings are rejected.
JSON need not be canonical, but sign the same serialization you transmit.
Duplicate authentication headers and duplicate JSON object keys are rejected.

All responses after verification, including errors, carry
`X-CF-Tester-Signature`, calculated over the exact returned response bytes:

```text
nonce + '\n' + str(status_code) + '\n' + sha256(response_bytes).hexdigest()
```

Authentication failures and pre-verification malformed/oversized bodies are
unsigned. Raw bodies are capped at 64 KiB; body collection is capped at 10 seconds.
Drift is checked again after collection. Nonces persist across restarts; replay
returns signed 409. There are at most 4096 live nonce entries; saturation returns
signed 503 rather than evicting replay protection.

HEAD is not an API route and returns signed 405 after verification (or the
applicable authentication/query error). All HEAD responses send no body and
sign SHA-256 of empty wire bytes, even when Content-Length retains normal HEAD
metadata. Controllers should use the documented GET routes, not HEAD.

## Routes

All JSON failures use `{"error": "fixed_error_code"}`; reports contain no exception
messages. GET routes and cancellation reject nonempty bodies with signed 400.

### GET /v1/status

```json
{
  "enabled": true,
  "active_run_id": null,
  "mode": "remote-waf",
  "profiles": ["smoke", "sqli", "xss", "command", "traversal", "ssti", "ldap", "xxe", "ssrf", "prototype", "log4j", "scanner", "managed", "all"],
  "limitations": ["..."]
}
```

`active_run_id` is null or the active canonical UUID string. Limitations are
returned in full at runtime; the placeholder above is documentation only.

### POST /v1/runs

| Field | Requirement/default |
| --- | --- |
| `run_id` | Required, canonical lowercase hyphenated UUID string. |
| `targets` | Required, 1-10 public HTTPS DNS URLs, port omitted or 443. Literal ASCII base paths only; no IP literals, credentials, query, fragment, encodings, or dot segments. DNS is checked during execution, not submission. |
| `profiles` | Nonempty array of fixed supported names; defaults to `["all"]`. Selecting `all` normalizes to `["all"]`; duplicates collapse into catalogue order. Smoke uses GET. |
| `max_requests` | Integer 1-500, default 500. |
| `rate_per_second` | Finite number 0.1-2, default 1. |
| `max_runtime_seconds` | Integer 1-600, default 600. |
| `timeout_seconds` | Integer 1-30, default 10; effective timeout is clamped to remaining runtime and includes DNS. |
| `max_redirects` | Integer 1-5, default 5; at most this many redirects after the original send. |
| `authorization` | Required, literal boolean `true`. |

Unknown fields, invalid JSON, and invalid specs return signed 400. Targets
normalize to lowercase DNS, omit explicit 443, preserve path case, and gain `/`
if the path is empty. Duplicate targets collapse. DNS failures become bounded
error attempts, never private-network requests.

Before scheduling, the service atomically persists a unique run-ID claim. A
successful submission returns 202 with exactly:

```json
{"run_id": "canonical-uuid", "status": "queued", "spec": {"normalized": "spec"}}
```

An active run returns signed 409 `executor_busy`. Any previously claimed ID
returns signed 409 `duplicate_run_id`, even with changed spec or after cancellation,
restart, interruption, or attempt-detail retention expiry. At 1000 permanently
retained IDs, new submissions return signed 503 `run_id_capacity_exhausted`.
There is no delete/reset route; preserving the state directory is necessary for
durable deduplication.

### GET /v1/runs/{run_id}

Returns the persisted report, never reruns traffic:

```json
{
  "run_id": "canonical-uuid",
  "status": "completed",
  "mode": "remote-waf",
  "spec": {"normalized": "spec"},
  "started_at": "UTC ISO-8601 or null",
  "finished_at": "UTC ISO-8601 or null",
  "summary": {
    "planned_cases": 1,
    "attempts": 1,
    "observations": {"allowed": 1, "challenged": 0, "cloudflare_block_response": 0, "inconclusive": 0, "error": 0}
  },
  "attempts": [],
  "limitations": ["..."]
}
```

Statuses: `queued`, `running`, `completed`, `budget_exhausted`, `cancelled`,
`interrupted`, `error`. `planned_cases` counts original catalogue requests;
`attempts` and observations count all hop slots, including failed DNS/connect
reservations. Attempt evidence includes case/category/control, hop index,
method, sanitized destination, status, validated Ray ID, selected public IP,
bounded bytes-inspected count, redirect disposition, and a fixed error code.
Each slot is persisted before sending and updated after observation.

`redirect` is null, `pending`, `followed`, `not_followed`, `failed`, `hop_limit`,
`unsafe_or_missing_destination`, or `loop`. `pending` means a redirect URL was
accepted but no next-hop response has been observed. Only an actual next-hop
HTTP status confirms `followed`; a next-hop block/challenge still confirms the
redirect request received a response, without proving origin delivery.
`failed` means transport started but returned no confirmed HTTP status.
`not_followed` means there is no confirmed response because DNS/URL validation
failed or execution stopped; cancellation can leave physical delivery unknown.
`redirect_reason` is null or a fixed code: `dns_or_url_failure`,
`transport_failure`, `request_budget`, `runtime_budget`,
`cancelled_or_runtime_limit`, `execution_interrupted`, or `interrupted`.
On cancellation/budget exit, pending dispositions become `not_followed`; startup
does the same for interrupted inflight reports. No raw redirect destination or
exception text is stored in these fields.

Only the latest 20 reports retain attempt details; older reports retain all
summary/spec/status metadata and their permanent ID claim, with an explicit
retention limitation. Each report/response is capped at 2 MB (2,000,000 bytes). Invalid UUIDs
return signed 400; unknown IDs return signed 404.

### GET /v1/runs

Returns `{"runs": [<metadata>]}` for the latest 20 submitted runs, newest first.
Metadata fields: `run_id`, `status`, `mode`, `spec`, `started_at`, `finished_at`,
`summary`. No query parameters or attempt arrays are exposed here.

### POST /v1/runs/{run_id}/cancel

Send an empty body. Requests cancellation and interrupts in-flight DNS/request/
rate waits. Returns 200 with `{"run_id": <id>, "status": <current-status>,
"cancel_requested": <boolean>}`. The boolean is true when the resulting status
is `cancelled`; terminal runs are not rerun or rewritten. Invalid/unknown IDs
return signed 400/404. The controller must still handle a run completing just
before cancellation.

## Redirects And Evidence

Redirects are manual, only for 301/302/303/307/308, and never follow observed
blocks or challenges. POST becomes GET on 301/302; 303 changes non-HEAD to GET;
307/308 preserve method/body. Only safe default headers and framing for a
preserved body survive redirects; original Cookie, Authorization, probe, and
other unsafe headers do not. Set-Cookie is never replayed.

Every hop, including same-host redirects, validates its HTTPS/443 DNS URL and
resolves DNS afresh. Every returned address must be public unicast; mixed answers
are rejected. The first validated address is pinned without fallback. TLS uses
the URL hostname for SNI/hostname validation with required chain verification.
Environment proxies are ignored, cookies are dummy-only, and aiohttp 3.13.3
implicit retries are disabled. Loops and hop limits terminate inconclusively.
All physical hops share the same global count, send-spacing, and runtime budgets.
Mapped, 6to4, and Teredo IPv6 addresses are explicitly rejected independently of
the Python runtime's global-address classification, as are reserved/scoped/
site-local addresses and Azure's platform-service address.
Spacing is conservative: a full `1 / rate_per_second` period starts after every
attempt completes or fails, including DNS/connect failures. Slow TCP/TLS setup
therefore cannot collapse physical HTTP-send spacing; actual traffic can be
slower than the requested rate, and all these waits consume runtime budget.

Bodies are inspected only up to 64 KiB in memory and are not persisted. Raw
Location and response headers/cookies are not saved; recorded destinations omit
query and fragment. Exception text is never saved. Fixed catalogue payloads are
not arbitrary exploit inputs. There is no Cloudflare correlation or configuration
inventory, individual-rule proof, exploit-success finding, protection score, or
universal coverage claim. 2xx is only `allowed`; terminal 3xx is inconclusive.

## Offline Verification

Required packages are listed in `requirements-executor.txt`; source-tree tests additionally require
pytest, pytest-asyncio, rich, and requests because the existing source package has
an eager `modules/__init__.py`. Use an isolated test environment. No live, browser,
deployment, or container execution is necessary:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -o addopts='' tests/unit/test_remote_runner.py tests/unit/test_remote_service.py
```

`-o addopts=''` disables the existing whole-project coverage output/threshold.
API tests skip when FastAPI is absent. Both modules deny socket DNS/connect calls;
transports and runners are mocked, and ASGI tests use injected fake keys/private
temporary state, not configured credentials or network listeners.
The Docker-layout contract test copies only the Dockerfile's explicit application
files into a private temporary directory and imports them in an isolated Python
subprocess. DNS/connect, key/state startup access, and guarded/classic imports
are denied; optional rich/requests/browser packages are modeled as unavailable.
It needs no Docker daemon or image build. FastAPI 0.115.6,
uvicorn 0.32.1, and httpx 0.28.1 are pinned to match controller integration;
rich/requests are omitted from the minimal image and remain dependencies only of
the existing source-tree package imports during tests. httpx's optional Rich CLI
import does not prevent execution when Rich is absent.
The safe Python CI job installs executor dependencies so API tests do not silently
skip there. Cross-repository controller checks are documented in
[GCP Integration](GCP_INTEGRATION.md).
