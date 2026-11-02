import test from "node:test";
import assert from "node:assert/strict";
import { buildPolicy, capturedPages } from "./policy.js";

test("active UI authorization keeps exact scope, methods, expiry and confirmation", () => {
  const policy = buildPolicy({
    target_url: "https://example.test/search",
    mode: "custom-active",
    allowed_endpoints_str: "GET /search\nPOST /search\nGET /robots.txt",
    policy_expires_at: "2026-11-02T14:00:00+05:00",
    authorization_confirmed: true,
  }, ["/internal"]);
  assert.deepEqual(policy, {
    mode: "custom-active", scope_origin: "https://example.test",
    allowed_endpoints: [{ path: "/search", methods: ["GET", "POST"] }, { path: "/robots.txt", methods: ["GET"] }],
    excluded_paths: ["/internal"], expires_at: "2026-11-02T09:00:00.000Z", authorization_confirmed: true,
  });
});

test("passive UI supplies captures without replacing field or token values", () => {
  const content = '<form><input name="csrf" value="real-token"></form>';
  assert.deepEqual(capturedPages({target_url: "https://example.test/", captured_content: content, captured_headers: ""}),
    [{url: "https://example.test/", content, headers: null}]);
  assert.throws(() => capturedPages({captured_content: ""}), /no target requests/);
});
