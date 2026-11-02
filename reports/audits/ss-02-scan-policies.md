# SS-02 implementation contract

Implemented 2 November 2026. This supersedes SS-02's execution behavior in the
31 October audit; the audit remains a historical snapshot. Other findings remain open.

## Passive is the API default

`POST /api/v1/scan/` defaults to `mode: "passive"`. It analyzes supplied
`captured_pages` only: no DNS resolution, crawl, robots fetch, link following,
form submission, XSS, SQLi or sensitive-file requests. Even GET can change state,
so passive mode never fetches the target. Each capture's origin must match the
target's normalized scheme, hostname and effective port, and request exclusions apply.
Missing captured response headers skip header analysis. An empty capture list
performs zero analysis; the API description displays the supplied capture count.

Example body (send the configured `X-API-Key` header):

```json
{
  "target_url": "https://staging.example/search",
  "captured_pages": [{
    "url": "https://staging.example/search",
    "content": "<html>Captured response</html>",
    "headers": {"Content-Type": "text/html"}
  }]
}
```

## Active authorization

First explicitly authorize a policy with `POST /api/v1/scan/policies`:

```json
{
  "mode": "custom-active",
  "scope_origin": "https://staging.example",
  "allowed_endpoints": [
    {"path": "/search", "methods": ["GET", "POST"]},
    {"path": "/robots.txt", "methods": ["GET"]}
  ],
  "excluded_paths": ["/internal"],
  "expires_at": "2026-11-02T19:00:00+05:00",
  "authorization_confirmed": true
}
```

Replace the example expiry with a future timezone-aware time within seven days.
`safe-active` permits only GET/HEAD; `custom-active` permits explicitly listed
GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE pairs. Neither mode guarantees absence of
side effects. Exact paths are case-sensitive and trailing slashes matter. No globs,
encoded paths, query strings, or dot segments are accepted as endpoint grants.
Queries remain attached to requests; endpoint grants permit query variation on
that exact path. Sensitive operations in query strings are blocked too.

The server assigns a policy ID, version 1, authorization timestamp, and SHA-256
fingerprint of the authenticated API credential. The fingerprint identifies the
single shared credential, not a verified person or asset owner. This is explicit
operator attestation, not proof of legal authority. There is no policy update API.

Start with `{"target_url":"https://staging.example/search",
"mode":"custom-active","policy_id":"<returned policy_id>"}`. The target
requires an allowed GET. The API rejects missing, unknown, expired, wrong-mode,
wrong-origin and wrong-credential grants before creating an active job. Every
crawler/plugin send rechecks method, exact endpoint, origin, expiry, exclusions,
and existing target-address checks. Crawler redirects require another approved
GET; plugin redirects are not followed. Discovered form actions are never added
to the crawl queue. robots.txt is fetched only when GET /robots.txt is authorized.
Plugin request options cannot enable automatic redirects or HTTPX authentication
flows that could send extra unvalidated requests. Explicit `follow_redirects=False`
is supported for sensitive-file probes. All methods share the same crawler boundary.

Logout/signout, checkout/purchase/payment/billing, deletion/removal, account recovery,
password, account/user/registration, settings, email/send and transfer workflows
are conservatively excluded in every active profile. Explicit permissions cannot
override these exclusions. Add application-specific path-prefix exclusions for
other sensitive workflows. Names cannot identify every business operation, so
operators must review endpoint behavior before granting it, including GET routes.

Form probes serialize captured successful controls and change only one eligible
editable field per request. Hidden values, ordinary sibling values, textarea/select
values, checked controls, duplicate names and anti-CSRF token values are retained.
Token-like/secret fields are never fuzzed. Disabled, unchecked and submit controls
are omitted; unsupported encoding/method forms and framework method overrides are skipped. Tokens can expire or
be single-use: the scanner does not refresh tokens or replay failed submissions.

## Records and limitations

Policies and metadata-only request records are stored in local SQLite at
`backend/data/scan-policy.sqlite3`, configurable with `SENTINAL_SCAN_POLICY_DB`.
Protect and persist this file as deployment authorization data. Registration must
commit before a policy can be used; each request audit row commits before send.
Rows include request/scan/policy IDs, policy version, method, origin, path,
authorization timestamp, outcome and response status. Bodies, query values,
headers, credentials and tokens are omitted. A failed/cancelled send is recorded
as `uncertain` and is not automatically retried. An interrupted process can leave
`authorized` without a response; do not interpret that as proof no send occurred.

`GET /api/v1/scan/policies/{policy_id}` retrieves the stored policy;
`GET /api/v1/scan/{scan_id}/requests` retrieves its durable send records, even
after the in-memory scan history is lost. Scan responses expose the selected mode,
policy snapshot and limitations. The UI shows capture-only behavior or explicit
active grants/expiry before launch, and stored policy details afterward. JSON
exports include that snapshot. Captured HTML and credential values are not part
of policy records.

This is a single-operator local policy store, not durable scan scheduling/history,
multi-user authorization, request budgets, revocation, or DNS-to-connection pinning.
SS-03/04/05/07/09 remain separate work. Existing active detection accuracy and
coverage limitations remain; passive zero findings cannot establish absence of XSS
or SQLi. No live target scan is required to validate this change.

## Offline acceptance

Run `python -m pytest -q` from `backend/`. An autouse guard blocks real HTTP
connections; MockTransport fixtures remain available. `test_scan_policy.py`
executes the real engine and asserts zero passive handler calls (including
state-changing GET and checkout handlers), exact active send scope and audit rows,
form/token preservation, and denials for missing/mismatched/expired policies,
methods, origins, ports, paths, query operations and redirects. Frontend `npm test`
also checks policy payloads and capture preservation. Run the repository's pinned
Ruff and Bandit checks and frontend lint/build before release.

`test_plugin_safety.py` also exercises all initialized plugins through the real
engine with mocked DNS: off-scope/unsafe form actions, credential isolation,
excluded sensitive files, approved probe execution, redirect/auth options,
alternate methods, stop, DNS changes between sends, and safe-active handler state.
The 2 November backend run passed all 63 tests (44 in the focused safety/plugin
suite). DNS-to-connection pinning remains unqualified; active grants cannot
guarantee the absence of application side effects.
