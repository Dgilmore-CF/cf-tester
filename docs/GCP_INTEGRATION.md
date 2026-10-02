# GCP Control-Plane Integration

## Source Status

The integration is implemented across this repository and the related
`gcp-lab-consolidation` checkout at
`/Users/dgilmore/Opencode/gcp-lab-consolidation`. Supplying that absolute path is
sufficient for workspace access; no symlink or global filesystem-permission change
is needed. Treat tfvars, Terraform state, credentials, private inventories, and
logs as sensitive.

This is source integration with offline verification, not a deployment. No image
has been published, secret provisioned, infrastructure applied, or live target
probed as part of this integration.

## Architecture

```text
Operator browser, localhost via authenticated IAP TCP forwarding
    -> trafficgen-ctrl dashboard, Evidence > WAF executor
    -> signed private HTTP control channel
    -> dedicated non-WARP GCE VM, immutable executor container
    -> verified TLS, pinned public DNS, authorized HTTPS targets/redirects
```

The workstation may remain on WARP; executor traffic uses ordinary GCP internet
egress. Do not run WAF jobs on WARP agents, a vulnerable testbed host, or through
`app/traffic/actions.py`, whose ordinary HTTP action path disables TLS verification.
The executor's source IP, region, and ASN differ from the workstation. They are
distinct experiment environments; differences are not solely WAF configuration.

## Implemented Components

In this repository:

- `cf_tester_service.py`: idle, HMAC-authenticated single-worker API with durable
  run-ID deduplication, nonce replay protection, and private bounded reports.
- `modules/remote_runner.py`: fixed-catalogue probes with verified TLS, per-hop
  DNS validation/pinning, automatic public HTTPS redirects, and shared budgets.
- `Dockerfile.executor` and `requirements-executor.txt`: minimal Python 3.13
  namespace-package image; classic/guarded runners and browser engines are omitted.
- `tests/unit/test_remote_service.py` and `test_remote_runner.py`: offline service,
  transport, lifecycle, storage, and Docker-layout import contracts.

In `gcp-lab-consolidation`:

- `modules/apps/traffic-generator/app/waf.py`: operator-only controller routes,
  exact-byte request/response signing, private-IP endpoint restriction, and no POST
  retry or control-channel redirects.
- `app/static/waf.js` and `app/templates/index.html`: start, cancel, history,
  download, explicit authorization, and GET-only uncertain-submission reconciliation.
- `app/main.py`: global kill requests remote cancellation and warns when it cannot
  be confirmed. A kill generation latches across in-flight submissions, including
  lost acknowledgements and kill-on/kill-off races.
- `modules/workloads/waf-executor/` and
  `environments/consolidated/*waf-executor.tf`: disabled-by-default workload,
  dedicated executor/controller identities, runtime Secret Manager key retrieval,
  controller-only firewall allowance, and private API output.
- `modules/workloads/traffic-generator/`: endpoint/key-file provisioning and
  uvicorn `--no-proxy-headers`, preserving the actual operator connection address.

## Execution Contract

The service runs `remote-waf`, neither the regular CLI nor guarded `waf_lab` mode.
The UI defaults to a benign smoke control and offers the full fixed catalogue;
the API defaults to `all` when profiles are omitted. Reduced-impact signatures
can still harm vulnerable applications. Every submission must explicitly assert
authorization for original targets, catalogue paths, and followed destinations.

Redirects are automatic only to public DNS HTTPS/443 destinations, bounded by
five hops and the run-wide budgets. Private/metadata/loopback destinations,
mixed public/private DNS answers, downgrades, cookies, and unsafe forwarded
headers are rejected. Every hop consumes the shared request/runtime budget.
Conservative rate spacing starts after the preceding attempt completes or fails.

The service starts idle. Restarts interrupt old jobs without replay; run IDs
remain claimed. The controller never retries submission POSTs, retains uncertain
UUIDs in the browser session, and requires GET confirmation or an explicit
side-effect warning dismissal before another submission.

There is no remote Cloudflare inventory/events correlation, individual-rule
proof, exploit-success finding, protection score, or universal coverage claim.
See [Remote Service](remote-service.md) for the full API and evidence contract.
Guarded `waf_lab_*` tools retain their separate complete-review/digest/fresh-approval
contract and are not called by this service.

## Deployment Boundary

Use the related repository's `docs/runbooks/waf-executor.md` for a separately
authorized release. It requires an externally published immutable image, a
distinct existing Secret Manager signing-key secret, both controller feature
gates, and explicit `enable_waf_executor=true`. Terraform never stores key values.
Only the dedicated controller and executor identities receive key access; WARP
agents do not.

The private API is protected by signed requests and an allow/deny pair preceding
the shared VPC's broad TCP rule. Review actual hierarchical firewall precedence,
network-tag permissions, IAM propagation, and egress before deployment. The
controller key is root-owned `0640`; executor state is UID/GID 10001, mode `0700`.
Boot-disk state survives service restarts, not VM destruction; no backup is added.

Existing compute ignores startup-script changes, and controller bootstrap
preserves hot-deployed files. Source updates or an ordinary reboot do not install
this release. Existing VMs need a reviewed manual installation/restart; attaching
the dedicated controller identity may require downtime. Coordinate key rotation
with both services. Update the lab changelog/wiki together when carrying out the
actual deployment, not as a claim that this source work has already shipped.

## Offline Checks

With the executor dependencies and pytest installed in an isolated environment:

```bash
python -m pytest -o addopts='' tests/unit/test_remote_runner.py tests/unit/test_remote_service.py
```

From the GCP controller directory, use an environment containing its dependencies
plus the executor test dependencies:

```bash
CF_TESTER_SOURCE=/absolute/path/to/cf-tester python -m unittest discover -s tests -v
node --test tests/test_waf_ui.mjs
```

The cross-repository ASGI tests inject an inert runner, synthetic keys, and
temporary private state while denying DNS/connect calls. Without
`CF_TESTER_SOURCE`, only those optional cross-repository tests skip; ordinary
controller tests still run. Bootstrap shell/Python parsing and scoped Terraform
formatting checks are documented in the GCP runbook. None of these checks deploys
infrastructure or sends target probes.
