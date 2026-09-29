# Mihakk

Created by Rawabi Alharbi

Mihakk is a **defensive web-application fuzzer**. It generates unexpected inputs to help an application owner find and fix crashes and unusual behavior.

> **Findings are indicators that require verification, not confirmed vulnerabilities.**

## Authorized use and safety limits

Use Mihakk **only** against applications you own or are explicitly authorized to test. These safeguards are enforced by the engine, not merely by the UI:

- **No run without an authorization acknowledgement.** The acknowledgement names the responsible person and time, is bound to the scope digest, and expires after 24 hours. An acknowledgement for a narrow scope cannot authorize a broader one.
- **Strict allowlist.** Host, port, path prefixes, and methods are specified. Host wildcards are not accepted. Scope is checked before every request and after every redirect.
- **Address pinning.** The hostname is resolved once, every resulting address is checked, and the connection is made to the verified numeric address. There is no DNS-change window between validation and connection.
- **Explicit private-address authorization.** Public addresses do not need to be listed separately because the hostname already constrains them. Loopback and private addresses require individual addresses or narrow ranges in `allowed_addresses`: at least /24 for IPv4 or /120 for IPv6. Broad ranges such as `10.0.0.0/8` are rejected as configuration.
- **The address list is part of the scope digest.** Changing it invalidates the acknowledgement until authorization is renewed.
- **Mandatory positive limits.** Request rate, total requests, concurrency, run duration, per-request timeout, and response size are required. There is no unlimited setting.
- **Every redirect hop consumes a request.** With a total budget of one, the first request may be sent but the redirect is refused; the target receives no second request.
- **HTTPS certificate verification stays enabled.** A trust root can be added for a local self-signed application, but there is no skip-verification option.
- **Immediate stop** interrupts in-flight requests as well as preventing new ones.
- **Sensitive values are redacted** from logs and reports. Saved cases store a regeneration recipe rather than the actual request, so request secrets are not written to the case store.
- **Target data is not sent to an external service.**
- The bundled local testbed is isolated and is not exposed to the internet.

### Address ranges that cannot be authorized

Even an explicit, narrow configuration cannot permit the following ranges in this MVP:

| Range | Examples |
|---|---|
| Link-local (IPv4 and IPv6) | `169.254.0.0/16`, including the metadata address `169.254.169.254`; `fe80::/10` |
| Multicast, including interface-local | `224.0.0.0/4`; `ff00::/8` |
| Unspecified | `0.0.0.0`; `::` |
| Broadcast | `255.255.255.255` |

A metadata endpoint can expose cloud credentials. Allowing one configuration error to reach it is not an acceptable trade-off for this tool. `Scope.Validate` rejects a configuration that lists these ranges, and `Target.AuthorisesAddress` rejects them again when opening a connection. To test an application currently on a link-local address, give it an explicitly authorized loopback or narrow private address instead.

## Project status

The local MVP through phase 8 is implemented. See the [operations guide](docs/operations.md) for the runbook and the limits of the validation performed so far. Isolated local test results are **not** production-deployment validation.

| Phase | Scope | Status |
|---|---|---|
| 1 | Shared schemas and Go safety layer | Complete |
| 2 | Request samples and deterministic mutation | Complete |
| 3 | Isolated `testbed` | Complete |
| 4 | Execution, detection, saved cases, and CLI | Complete |
| 5 | Control API, FastAPI orchestrator, and SQLite | Complete |
| 6 | Aggregation, classification, and JSON/HTML reports | Complete |
| 7 | Dashboard | Complete |
| 8a | Owner-application stack, Unix-socket Control API, internal target network, and secrets | Complete |
| 8b | Live resilience tests: resumption, restart, and concurrency | Complete |
| 8c | Operations documentation and tested quickstart | Complete |

## Deterministic mutation

Mihakk starts with **valid request samples** that the application owner knows the target accepts. Case `i` is a pure function of:

```text
(seed, engine version, sample digest, configuration digest, i)
```

Generation reads no mutable shared state or clock and does not depend on which worker runs a case or when it finishes. Sorting by case number restores the same input sequence across worker counts, processes, and machines. This is a guarantee about **inputs**, not target behavior: status codes, timings, and even whether an indicator appears can change on replay.

The generator is specified inside this project using SHA-256 in counter mode. It does not use `math/rand`, whose sequence for a seed is a property of the Go version and could change silently on an upgrade.

### Mutations and deliberate exclusions

Mutators create **structural anomalies**: boundary values, type changes, truncation, excessive length, damaged encodings, and single separator characters. They do **not** generate ready-made exploits: no SQL-injection strings, script tags, template-injection probes, or authentication-bypass attempts. A single quote, angle bracket, backslash, newline, or NUL can expose parser mishandling without composing an attack.

- **Paths are not mutated.** Changing a path could leave the authorized prefix, waste the request budget on rejected cases, and confuse results.
- **Sensitive or destination-changing headers are never mutated.** `Host` and forwarding headers could change the destination; `Content-Length` and `Transfer-Encoding` could break consistency with the body; mutating `Authorization` or `Cookie` would generate authentication-bypass attempts. Mutable headers come from an allowlist, not a denylist.
- **Destination preservation is checked after generation.** Method, scheme, host, and path must still match the sample. The safety layer nevertheless checks scope before every request; generator checks do not replace that guard.
- **Size limits apply to final bytes.** `max_value_bytes` constrains a generated value; `max_body_bytes` and `max_url_bytes` constrain the complete generated request. An oversized original sample is rejected when the plan is built, not silently truncated.
- **Encoding expansion is counted.** Query/form re-encoding can turn a four-byte UTF-8 character into 12 percent-encoded characters; JSON escapes `<`, `>`, and `&`. Limits are checked on the re-encoded form at plan construction and again on every final case. If an expanding *field name* makes even an empty value too large, the sample is rejected.
- **Header names are case-insensitive.** A sample containing both `X-Tag` and `x-tag` merges values in sorted order of their original spelling. Go map keys that affect fingerprints or output—query names, JSON keys, form fields—are sorted before use.

Manual sample files are supported. OpenAPI loading is described below.

## The isolated `testbed`

The bundled testbed is a small, **deliberately flawed** web application using only Python's standard library. It needs no package installation during its build or network access to run.

| Endpoint | Behavior |
|---|---|
| `GET /api/health` | Fully stable response and size |
| `GET /api/items` | Comparison endpoint: mutations of `page`, `limit`, and `q` still produce a quick 200 |
| `POST /api/orders` | Planted 5xx when `qty` has the wrong type (null, array, or object) |
| `GET,POST /api/search` | Bounded planted slowdown when the index cannot be used |

### Isolation is enforced and tested

The testbed has **no `ports:` entry** and is reachable only inside Docker at `http://testbed:8000`. Its network is `internal: true`, so the testbed itself has no external route.

```bash
./scripts/verify-testbed-isolation.sh
```

The six checks include two static checks of the **resolved** Compose configuration and four live checks: no host binding of any testbed port, no default kernel route, external connection failure specifically with `ENETUNREACH`, and a positive control showing that the testbed actually works.

A failed probe of `localhost:8000` would not prove isolation: another application may own that host port. Instead, the check reads the testbed container's requested bindings (`HostConfig.PortBindings`) and actual bindings (`NetworkSettings.Ports`) for **any** port. Docker can silently ignore a `ports:` request on an internal network, making the requested and actual bindings differ.

Static restrictions apply to the **testbed service**, not every service. The dashboard/API legitimately need a loopback host port. Every network attached to the testbed must be internal; the existence of one internal network is insufficient if a second interface provides an external route. The engine may join the testbed's internal network without changing that rule. The static checker is `scripts/check_testbed_isolation.py`, with tests in `scripts/test_isolation_checks.py`.

The isolation script restores the container to its prior state rather than running `compose down` on a shared project:

| State before check | State after check |
|---|---|
| Absent | Created, then removed |
| Existing and stopped | Started with `start`, then stopped without deletion |
| Running | Left running |

`scripts/test-isolation-scenarios.sh` covers an unrelated service publishing port 8000, the testbed publishing a different port, and each of the three prior container states.

### Unable to verify is not a pass

A failed external command, malformed JSON, `null`, or an unexpected structure is **`UNVERIFIED` with a nonzero exit**, never an empty port table or clean configuration:

```text
passed: 5   failed: 0   unverified: 1
TESTBED ISOLATION NOT VERIFIED (1 check(s) could not be evaluated)
```

A confirmed violation and an inability to check require different remediation, but neither permits an isolation claim. The in-container probe must report all three named checks—default route, external connectivity, and testbed access—and its exit code must agree with the report. A report containing one successful check cannot stand in for the other two.

The strict readers are `check_container_ports.py`, `check_testbed_isolation.py`, and `check_probe_report.py`. Their exit meanings are 0 = clean, 1 = violation, 2 = unverifiable. `scripts/test-unverified-paths.sh` replaces one `docker` call at a time with a failing stub and verifies a nonzero exit and `UNVERIFIED`, then runs an uncorrupted control.

The external-connectivity probe targets documentation-only `192.0.2.1` (TEST-NET-1), not a public site. **Only `ENETUNREACH` proves the needed property**: an externally connected container might also fail to reach that address, but only after sending a packet and timing out. Mutation checks confirm that publishing a testbed port or removing `internal: true` fails isolation verification.

### Rules for Docker test scripts

These rules are enforced by tests because an earlier live integration script initially ran `down -v --remove-orphans` against a shared Compose project, which could have removed operator volumes:

1. **Use an independent temporary Compose project and clean only what that script created.** `-p` alone is insufficient because the real file pins global `container_name`, network `name`, and volume `name` values. `scripts/isolated_compose.py` derives a temporary file from the *resolved committed configuration* and removes those pinned names. Read-only checks may inspect the real project.
2. **Never use `down -v` or `--remove-orphans` on a shared or potentially occupied project.** They are acceptable only inside the test's own temporary project. An explicit guard refuses teardown of the shared project; cleanup traps cover `EXIT INT TERM`.
3. **Inspect the container's own port bindings**, both requested and actual, for every port. Failure to connect to a fixed host port says nothing about that container. An unreadable inspection is `UNVERIFIED`, not `PASS`.
4. **Never `source` or execute data derived from an external response.** A previous `KEY=value`-then-`source` pattern executed an injected `$(...)`. `read_run_report.py` now validates values and emits tab-separated verdict lines that the shell *reads*; control characters cannot forge a verdict.
5. **Fail closed when inventory cannot establish ownership.** `claim_name.py` uses both command output and exit code: 0 = free, 1 = already exists (do not overwrite or delete), 2 = unverifiable (refuse the name).
6. **Keep the protected decoy inside the destructive command's reach without using the real project's names.** The live test owns a representative stack with unique `mihakk-decoy-<pid>-<ts>` names, derived from the committed file. It points the command under test to that file through `MIHAKK_COMPOSE_FILE`. A regression to “use the named project, then `down -v`” destroys the decoy and is detected.

`test_read_run_report.py` exercises shell injection, unreadable inputs, derived projects, name guards, and case-ID matching. `scripts/test-orchestrator-scenarios.sh` verifies that the decoy's identity, state, and data survive both successful and interrupted runs while the interrupted run removes its own resources.

### Bounded planted behaviors

`SLOW_PATH_DELAY_SECONDS = 0.4` is a fixed delay, **not a function of input length**. A two-character query and a 20,000-character query wait the same time; otherwise a mutation could turn this helper into a denial-of-service tool.

The planted 5xx is an exception caught by a top-level handler, not a crash. Fifty consecutive failing requests followed by a good request leave the process running. A nonnumeric text `qty` returns an ordinary 400, not the planted 5xx.

The JSON mutator set has 19 mutators. A field receives `mutations_per_target` consecutive mutators starting at a derived rotation offset. If that count is smaller than the set, a field may never see some mutators. In the testbed, the default of 8 missed the planted 5xx for two of four seeds; 20 or more reached both planted behaviors for every seed tried.

```bash
./scripts/go.sh run ./cmd/mihakk plan \
  -corpus /src/testbed/corpus.json -seed demo -mutations-per-target 24
```

## Execution and detection

```bash
# End-to-end run against the isolated testbed
./scripts/test-integration-testbed.sh
```

### Every request uses the guarded client

The `runner` package owns no HTTP client, transport, or socket. Its only way out is `safety.Client`, so a mutation that attempts to rewrite its destination—and even `reproduce`—cannot bypass scope checks, address pinning, rate limits, request budgets, or the kill switch.

`enforcement_test.go` structurally scans Go code outside `safety` and refuses calls capable of sending traffic, such as `http.Get`, `http.Client`, and `net.Dial`. A negative control proves the scanner detects a bare `http.Get`. Behavioral tests also use samples that try another host, an out-of-prefix path, a forged `Host` header, or a redirect to an unauthorized host. The unauthorized target receives **zero requests**, and each refusal is audited as `not_sent`.

### Indicators, not vulnerabilities

Every saved case has an **indicator type**, a comprehensible **reason** with the baseline used for comparison, and a full **regeneration recipe**. Its state is always `indicator_needs_verification`.

The engine records what it observed, not a confidence score it cannot justify. Detailed classification and confidence belong to the orchestrator; the confidence field is optional in `schemas/case.schema.json`. Baselines send each unmutated sample three times before mutations to measure median, spread, and size. A fivefold increase from a 2 ms baseline is only 10 ms and may be scheduling noise, so timing detection also has a **250 ms absolute minimum**. Ordinary 4xx responses are not indicators.

### Reproduction is subject to the same rules

`mihakk reproduce <case-id>` rechecks a current, scope-bound authorization acknowledgement, scope, and all limits. It regenerates the request from the saved seed, case number, and mutation settings rather than replaying request bytes from disk.

The result reports `exact` or `drifted`, explains differences, and says whether the indicator reappeared. Reappearance does not prove a vulnerability; absence does not prove the original observation was wrong. If safety rules refuse the request, the outcome is **unknown**, not “did not reproduce.”

### Incomplete results are never presented as complete

A failure to save an observed case or audit event is not ignored. The run becomes `incomplete`, records the count and reason for losses, and `mihakk run` exits nonzero with an explicit warning:

```text
RESULTS INCOMPLETE
  8 observed indicator(s) could not be written to the case store ...;
  the saved results are a subset of what was found
  Do not read the saved cases as everything this run found.
```

A run that detected 16 indicators but saved two did **not** produce a complete result set. If even the session record cannot be saved, `Run` returns an error instead of an unverifiable summary. This covers direct storage failures; losses between engine and orchestrator are handled separately by the stream completeness contract.

### Audit trail and redaction

`data/audit.jsonl` records who started a run, the exact acknowledgement and its time, scope digest, targets, effective limits, seed, stop time/reason/statistics, every refused request, and every reproduction.

Redaction has two layers. Redacting fields by name (`Authorization`, `password`) alone fails when a mutation makes the body unparsable. Known literal secret values from samples are also registered with the redactor and removed wherever they occur. A test searches both audit records and saved cases for five test secrets.

### Documented OpenAPI subset

OpenAPI 3.x in **JSON or YAML** is supported for `query`, `path`, and `header` parameters (path- or operation-level), simple `application/json` bodies, and local references under `#/components/…`. Unsupported features are reported by name rather than silently ignored: `oneOf`/`anyOf`/`allOf`/`not`, external references, multipart bodies, cookie parameters, and authentication schemes.

YAML is converted to JSON and passed through the **same parser** as JSON. Conversion to ordinary Go values and `encoding/json` makes key order deterministic. Equivalent documents yield identical samples and digests; field-by-field comparison and 100-parse determinism tests enforce that property.

```bash
./scripts/go.sh run ./cmd/mihakk plan -openapi testdata/openapi.example.yaml -seed demo
./scripts/go.sh run ./cmd/mihakk plan -openapi testdata/openapi.example.json -seed demo
# Both files produce the same digest.
```

`gopkg.in/yaml.v3` is pinned at `v3.0.1` and vendored under `engine/vendor/`, so engine builds and tests can run offline with `--network none`.

## Control API and orchestrator

```bash
./scripts/test-orchestrator.sh     # Containerized, network-free orchestrator tests
```

### The control surface is isolated

The Control API can start a run and therefore needs the same isolation discipline as the testbed:

- Since phase 8a it listens on **Unix socket** `/run/mihakk/control.sock`, in a volume mounted only by engine and orchestrator, with mode `0660` and group `10010`. The orchestrator uses `MIHAKK_ENGINE_URL=unix:/run/mihakk/control.sock`. The engine's only TCP listener is `/healthz` on loopback **inside its container**. The older `http://engine:8900` Control API endpoint is no longer used.
- The engine exposes no host `ports:` and joins internal networks only. Isolation checks verify no host port binding, and `scripts/test-stack.sh` reads `/proc/net/tcp` inside the engine container to require all listeners to be loopback-only.
- Every Control API endpoint except `/healthz` requires a shared token compared in constant time. The token comes from the environment, not a CLI argument visible in process listings. The engine refuses to start the API without a token.

`POST /v1/runs` accepts the same configuration as the CLI, runs the same `Prepare` path, and constructs the same guarded client. It has no field to bypass acknowledgement or expand scope; unknown fields are rejected. There is no endpoint that forwards arbitrary caller-authored requests.

The Python orchestrator does **not** send traffic to the target. Its path outward is the engine Control API. A test checks that the API exposes no `proxy`/`fetch`/`request` route and that `/v1/` routes are limited to `/v1/sessions`.

### Sequenced events and explicit loss

The event buffer is bounded so a slow consumer cannot grow memory without limit in a process sending traffic to someone else's application. The buffer assigns contiguous sequence numbers. A gap observed by a consumer therefore indicates actual loss, not a producer numbering artifact.

A follower resuming from an evicted point receives an **out-of-sequence** notice (`seq: 0`) before anything else, including the number lost:

```text
81 event(s) were evicted from the engine's buffer before they could be
delivered and are permanently lost; results derived from this stream are a
subset of what the run produced
```

### `completed` requires evidence

The orchestrator derives completeness from **stored rows**, not a claim. A session is `completed` only when the engine says it completed **and** stored events are contiguous from 1 through the engine's announced `total_seq`.

| Condition | Reported reason |
|---|---|
| Sequence hole | `gaps at sequence 3` |
| Engine eviction notice | `permanently lost` |
| Stream ends early | `ended early` |
| Missing `done` | `unknown`, with `interrupted` status |

The status is re-derived on every read. A later-discovered gap cannot leave a session claiming completion, and `/findings` carries the same warning. A contiguous stream proves the orchestrator received everything the engine *emitted*, not that the engine persisted everything it *observed*. If the engine reports `incomplete` because it could not write a case or audit event, that status and reason survive even with a perfect event sequence. `stopped` and `failed` remain distinct statuses; data completeness is shown separately in the `completeness` block.

### Restart and SQLite recovery

On startup, the orchestrator finds sessions that were `running` and follows each from its **last contiguously stored sequence** using `from_seq`. A guard prevents two followers for one session from racing to consume events or set the final status. After bounded failed reconnection attempts—for example, if a restarted engine no longer knows the run—the session becomes `interrupted` with a reason. It is not left `running` indefinitely.

The SQLite key `(session_id, seq)` makes duplicate delivery idempotent. Recovery asks for the last *contiguous* number, not the highest: if event 5 arrived but 4 did not, restarting from 3 gives event 4 another chance.

## Aggregation, classification, and reports

The engine **aggregates without judging**; the orchestrator **classifies and renders**:

```text
GET /v1/runs/{id}/aggregate         engine: deterministic raw aggregation
GET /v1/sessions/{id}/report        orchestrator: JSON or HTML, derived on each read
```

### Aggregation is a view, not a filter

The aggregation unit is a **(case, indicator) pair**, since one case can have several indicators. Its signature includes indicator type, mutation family, method, path without query, and response status for 5xx. The raw URL is not a useful grouping key because mutated query strings differ.

Four tested conservation properties prevent aggregation from hiding findings:

1. `Σ occurrences == indicator_instances`.
2. The union of group `case_ids` equals every stored case ID.
3. Declared totals must match independently calculated totals; disagreement is an error.
4. Every group stores its **complete** ID list. A report may display fewer if it states how many it omitted; the aggregate document may not silently truncate.

The aggregate has no timestamp, is byte-for-byte reproducible from stored data, and sorts groups by signature digest rather than map iteration order.

### Provenance of enforced scope

The snapshot comes from the `Scope` actually enforced by `safety.Client`: `client.Scope()`. `NewClient` clones the caller's scope, preventing a caller's later mutation from changing a running session's enforcement. `ScopeDigest`, `Targets`, audit records, and start responses all derive from that same snapshot.

A provenance test deliberately supplies a client scope different from `Config.Scope` and checks every recorded field follows the client. Recomputing a digest proves only internal consistency; provenance is what proves that the displayed scope was the one enforced.

| Scope record | Display |
|---|---|
| Present and consistent | Scope, with `allowed_addresses` redacted |
| Present but inconsistent | Explicitly marked inconsistent with a reason; never presented as proven |
| Absent | A **target summary** only, not a claim to show full scope |

`allowed_addresses` is omitted from shareable reports, while the digest remains based on the **full** scope. The orchestrator filters the field again rather than trusting the engine's filtering.

### Classification explains its reasoning

`confidence` means **confidence in the observation**, not severity. A 5xx is high confidence because the application acknowledged failure. Timeouts and connection errors are medium, with an explicit caveat that the engine cannot distinguish target failure from a problem en route. Slow or large responses are low confidence. Multiple mutation families can raise confidence; an unstable baseline can lower a baseline-dependent finding; a repeated reproduction can raise it.

“Not checked” is distinct from “checked but did not recur.” Each rule contributes a sentence to the report so a reader can evaluate the reasoning, not just the label.

### Completeness and safe HTML

Report completeness is the **worse of two independent answers**: whether the orchestrator received the full event stream and whether the engine persisted everything it observed. Each reason is attributed to its source because a broken stream and an engine write failure require different responses.

An engine-declared `incomplete` state is decisive even when some counters are zero. `failed` is likewise not complete. A `stopped` run is not automatically data-incomplete—everything produced before the stop may have been stored—but the report explicitly says the plan ended early. If declared aggregate totals disagree with calculated totals, both JSON and HTML endpoints return **502** with the conflicting numbers, rather than a 200 response whose warning readers might overlook.

HTML treats content as hostile because indicator reasons can include target response bytes and request previews can contain mutations. All values pass through one escaping function into **text nodes only**; even a request URL is displayed as text, not as a link. The report contains no JavaScript, event handlers, or external resources. Security policy is a real response header, with a meta fallback for a saved copy:

```text
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'none';
  form-action 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox
```

`scripts/check_report_html.py` parses the document tree, not a text search. Hostile strings such as `javascript:` **must remain visible as escaped text**, while executable elements, `on*` attributes, unsafe link schemes, style attributes, and external resources are rejected. The same checker is used by orchestrator tests; `scripts/` is mounted read-only into their container.

### Shared contract across Go and Python

`schemas/examples/aggregate.golden.json` is committed once. A Go test requires the engine to produce it byte-for-byte; a Python test requires the orchestrator to understand it. Intentional regeneration uses `scripts/go.sh test ./internal/aggregate/ -run TestGolden -update`. A live integration test checks the report through the orchestrator and Control API against case IDs actually delivered over the stream, and inspects real HTTP headers with `curl -D-`.

The unused `unexpected_status` schema enum value was removed rather than pretending the detector produced it. A bidirectional test now compares the committed schema enum with Go constants so neither a dead schema value nor an unlisted Go value can slip through.

## Dashboard and authentication

### Why the orchestrator needs authentication

Before the dashboard, the orchestrator relied on publication at `127.0.0.1` and was intended for scripts or `curl`. A browser also carries sessions for other sites, making cross-site requests and DNS rebinding relevant to an API that can start fuzzing runs.

Two tokens have different jobs and are **never interchangeable**: the dashboard token authenticates an operator; the Control API token reaches the engine and never leaves the orchestrator process for a page, JavaScript asset, or response. Tests search dashboard files and responses for the engine token.

`HttpOnly` prevents JavaScript from **reading** a cookie's value; it does not stop injected JavaScript from making authenticated requests because the browser attaches cookies automatically. CSRF defenses cannot rescue an XSS-compromised page. Preventing XSS is therefore essential, with other layers in support.

### Independently tested layers

| Layer | Purpose |
|---|---|
| Server-side session in SQLite | Real logout revocation; sessions persist across service restart until expiry or revocation |
| 12-hour absolute and 30-minute idle lifetime | Bounds exposure of a leaked cookie |
| Rotation on login and hourly | Prevents fixation and narrows the usefulness of a leaked session ID |
| Server-generated CSRF token in a custom header | Requires preflight and is checked server-side |
| `Origin` check | Refuses a cross-origin mutation even with a valid CSRF token |
| Allowlisted `Host` | Rejects DNS rebinding |
| Constant-time comparison, rate limiting, and lockout | One generic failure message reveals no guessing details |

Authentication is middleware, not an ad hoc call in each handler. Handler-level checks let FastAPI validate a request body *first* and return schema details (422) to an unauthenticated caller.

### Four pre-authentication routes, no login JavaScript

Only `/healthz`, `GET/POST /auth/login`, and `/assets/login.css` are available before login. The login page is a plain HTML form with no script and `script-src 'none'`; only that page allows `form-action 'self'`. Every other route—including reads—requires authentication because reports expose an operator's scope and application behavior. `main.py` declares the route list, and a test compares it with the actual application routes so a new unlisted route fails.

Scripts and `curl` authenticate with `Authorization: Bearer $MIHAKK_DASHBOARD_TOKEN`. Browsers use a cookie plus CSRF token. Both use the same secret, with no testing-only bypass; pytest tests authenticate for real. A bearer header is not ambient browser authority: browsers attach cookies automatically but do not attach an arbitrary `Authorization` header to cross-site requests.

### Render data as text, never markup

The static report's “no JavaScript” defense does not apply to the interactive dashboard. Instead, every API value reaches the page through `textContent` or `setAttribute` on an element created by dashboard code. There is no `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, or string passed to `setTimeout`. `scripts/check_dashboard_js.py` enforces this structurally without a browser and has a negative control proving it catches `document.write`.

A real response-header CSP uses `script-src 'self'` with no inline code or eval, `connect-src 'self'`, and `default-src 'none'`.

Target bytes can themselves say “vulnerability detected.” They must remain visible without becoming Mihakk's judgment. The UI keeps raw target output in `data-origin="target"`, under a label explaining that it is **raw target output, not Mihakk's assessment**. Mihakk's own verdict is in `data-origin="mihakk"`. Tests ensure target text never enters the verdict region. Dashboard-authored text makes no confirmed-vulnerability claim; raw target text is checked for non-executable rendering, not censored.

### Starting and viewing a run

The dashboard does **not** generate an authorization acknowledgement or scope digest. An operator uploads their configuration and reviews **scope, acknowledgement, limits, and default values** such as `mutations_per_target 8` and `max_value_bytes 512` before starting. The seed is generated with `crypto.getRandomValues` and displayed before and after start so reproduction remains possible. The engine's refusal is shown without reinterpretation.

Samples are where secrets may live, so their contents are **never shown**: only counts, IDs, and digests. Inputs are not placed in `localStorage`, `sessionStorage`, URLs, or the console. Scope and acknowledgement are treated as private operator data too—a path prefix or free-form statement might contain a token. “Clearing memory” in JavaScript means dropping references and displayed data; it does **not** guarantee the browser erased bytes from memory.

Local-only SVG charts show request counts over time and indicator distributions. There is no npm dependency or external chart resource. JavaScript does not recompute completeness or confidence; it displays server answers. Neutral, uniform bar colors keep a count from being mistaken for severity.

### Browser test

`scripts/test-dashboard-browser.sh` loads the dashboard in Chromium against a real orchestrator and a fake engine that streams hostile payloads into every field. It checks actual execution (`window.__pwned`), escaped visible text, delivered CSP headers, and separation of target output from Mihakk judgment. It does **not** reject a literal `javascript:` in page text; safely visible hostile text is the correct outcome.

The browser suite may need to obtain a Chromium image. It is separate from the fast suites; the structural JavaScript check covers the central no-markup property quickly and offline.

## Tests

```bash
./scripts/test-all.sh            # 5 fast suites: engine, orchestrator, testbed, secrets, loopback API
./scripts/test-all.sh --all      # 14 suites including live Docker tests
./scripts/test-all.sh --browser  # 15 suites including Chromium
```

`live-orchestrator` closes and resumes an NDJSON connection held by a **separate monitoring client** with `from_seq`. It also restarts the orchestrator during two active sessions and checks overlap, contiguous events, and completed cases. Closing that monitor is **not** the same as interrupting the orchestrator's own follower stream.

`live-faults` adds a Unix-socket fault proxy **only inside temporary test projects**. It cuts the orchestrator's actual follower stream, proves that the engine continues, and checks resumption from the last stored contiguous sequence. It also tests orchestrator restart, genuinely overlapping sessions with distinct events and results, and an unavailable resume that ends with a clear reason rather than remaining `running`. A deliberately broken variant of each scenario must fail for its intended reason. Each scenario checks cleanup and preservation of previously existing Docker resources and a neighboring volume.

`loopback-api` injects an HTTP proxy returning 500. It proves an ordinary client uses the proxy while two test helpers, after verifying a loopback destination, reach the local API directly without sending the proxy anything. It does not change the engine's target connections or global proxy settings. It also checks safe clock diagnostics when an authorization acknowledgement is rejected as being in the future, with no automatic retry or weaker authorization rule.

`operations-quickstart` executes the documented [local testbed walkthrough](docs/operations.md) in a temporary Compose project: secrets are generated outside the repository; the stack starts; an authorized run against the bundled testbed is followed; JSON and HTML reports are opened and checked for “indicators requiring verification.” It checks that Mihakk data and a neighboring owner's application survive shutdown and an injected startup failure, and cleans only its own resources. It uses **no public target** and does not create an acknowledgement on behalf of a real application's owner.

After all suites, `secret-scan` searches for the run's two tokens in every retained log and every tracked file. The runner stores the **complete output and exit code of each suite** and prints a failed suite's entire log, not just its tail. `scripts/test-runner-output.sh` checks this with a simulated failure; truncating output previously hid the actual failing check.

The tests above are local and isolated. Passing them does **not** verify a production deployment or an external target. Unverified areas, including actual IPv6 routing, backup restoration, and migration, remain documented in the operations guide.

## Requirements

Docker with Compose, plus Bash, Python 3, and `curl` on the host. Go does not need to be installed on the host: engine builds and tests run in a container with `--network none`.

## Running locally

### Start the stack

```bash
./scripts/init-secrets.sh           # Creates two tokens in ~/.config/mihakk/secrets.env (0600); prints neither
./scripts/stack.sh up               # Strictly parses that file; never sources it
./scripts/show-dashboard-token.sh   # Displays the dashboard login token in a terminal only
# Open http://127.0.0.1:8100/ (or the port selected by MIHAKK_PORT).
./scripts/stack.sh status
./scripts/stack.sh down             # No -v: engine and orchestrator data remain
```

For an entire local session—including scope digest, local acknowledgement, samples, seed, and JSON/HTML reports—follow the [testbed walkthrough in the operations guide](docs/operations.md). Do **not** reuse its acknowledgement for an application you own or a public target; authorization for those is a separate decision by their owner.

For an application you operate in another Compose project, create and attach an **internal** target network yourself, then start Mihakk against that existing network:

```bash
docker network create --internal my-target
docker network connect my-target my-app-container
./scripts/stack.sh up --target-network my-target
```

`stack.sh` rejects a network it cannot verify as an internal Docker network. It does not create the network, attach the application, or disconnect it. The target address must also be explicitly permitted by `allowed_addresses` where required.

### Engine CLI

```bash
# Format, vet, test, race-test, and build the engine.
./scripts/test-engine.sh

# Validate a configuration without sending any request.
./scripts/go.sh run ./cmd/mihakk scope-check -config testdata/session.example.json

# Check whether a URL is within that configuration's scope.
./scripts/go.sh run ./cmd/mihakk scope-check \
  -config testdata/session.example.json \
  -check-url "http://testbed:8000/api/items"
```

```bash
# Inspect a mutation plan without sending any request.
./scripts/go.sh run ./cmd/mihakk plan \
  -corpus testdata/corpus.example.json -seed demo-seed-1

# Run the same plan in separate processes and compare byte-for-byte digests.
./scripts/go.sh run ./cmd/mihakk plan -corpus testdata/corpus.example.json \
  -seed demo-seed-1 -dump | shasum -a 256
```

```bash
# Test the testbed inside a network-free container.
./scripts/test-testbed.sh

# Verify testbed isolation.
./scripts/verify-testbed-isolation.sh
```

`scripts/go.sh` forwards its arguments to Go inside the container.

## Repository layout

```text
engine/              Go engine: the only component that contacts a target
  internal/safety/    Scope, limits, authorization, redaction, guarded client
  internal/corpus/    Valid samples and their digest
  internal/mutate/    Deterministic case generation
  internal/runner/    Execution and reproduction
  internal/detect/    Baselines and indicators
  internal/store/     Saved sessions and cases
  internal/audit/     Audit trail
  internal/events/    Bounded, sequenced event stream
  internal/api/       Unix-socket Control API
orchestrator/        FastAPI service, SQLite, classification, and reports; never contacts a target
dashboard/           Lightweight web UI
testbed/             Isolated local app with two planted behaviors and a comparison endpoint
deploy/              Docker Compose; compose.target.yml joins an owner's internal network
schemas/             Contracts shared across services
scripts/             Stack management, containerized tools, and tests
```

## Outside this MVP

Generation-based and coverage-guided fuzzing, AI-generated remediation advice, CI/CD and issue-tracker integrations, WebSocket, and gRPC are not implemented. The architecture leaves room for them without claiming they exist today.

## License

The original Mihakk code and documentation are licensed under the [MIT License](LICENSE). Created by Rawabi Alharbi. This copyright notice does **not** claim ownership of bundled third-party components. The vendored `yaml.v3` library retains its own licenses and attributions in its [LICENSE](engine/vendor/gopkg.in/yaml.v3/LICENSE) and [NOTICE](engine/vendor/gopkg.in/yaml.v3/NOTICE), unchanged.
