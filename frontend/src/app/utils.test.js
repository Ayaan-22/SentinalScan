import test from "node:test";
import assert from "node:assert/strict";
import { safeHttpUrl, serializeReport } from "./utils.js";
import { demoScans } from "./demo.js";

test("finding links reject executable and malformed URLs", () => {
  for (const url of [
    "javascript:alert(1)",
    "data:text/html,test",
    "file:///etc/passwd",
    "not a url",
  ]) {
    assert.equal(safeHttpUrl(url), undefined);
  }
  assert.equal(
    safeHttpUrl("https://example.com/path?q=value"),
    "https://example.com/path?q=value",
  );
});

test("CSV preserves multiline evidence and neutralizes formula cells", () => {
  const text = serializeReport(
    "csv",
    null,
    [
      {
        description: '=HYPERLINK("https://example.com")',
        evidence: 'line one, "quoted"\nline two',
        remediation: "\t@SUM(1,2)",
        severity_score: 0,
      },
    ],
    false,
  );
  assert.ok(text.includes('"\'=HYPERLINK(""https://example.com"")"'));
  assert.ok(text.includes('"line one, ""quoted""\nline two"'));
  assert.ok(text.includes('"\'\t@SUM(1,2)"'));
  assert.ok(text.includes('"0"'));
});

test("JSON exports complete findings with provenance and allowlisted scan metadata", () => {
  const scan = {
    ...demoScans[0],
    auth_token: "must-not-export",
    recent_logs: ["private log"],
  };
  const report = JSON.parse(serializeReport("json", scan, scan.results, true));
  assert.equal(report.source, "illustrative-demo");
  assert.deepEqual(report.findings, scan.results);
  assert.equal(report.scan.auth_token, undefined);
  assert.equal(report.scan.recent_logs, undefined);
  assert.equal(report.scan.scan_id, scan.scan_id);
  assert.equal(
    JSON.parse(serializeReport("json", scan, [], false)).source,
    "scan-engine",
  );
});

test("each demo assessment has consistent counts, scope and detection times", () => {
  for (const scan of demoScans) {
    assert.equal(scan.results.length, scan.vulnerabilities_count);
    for (const finding of scan.results) {
      assert.equal(
        new URL(finding.url).origin,
        new URL(scan.target_url).origin,
      );
      assert.ok(finding.timestamp * 1000 >= Date.parse(scan.start_time));
      assert.ok(finding.timestamp * 1000 <= Date.parse(scan.end_time));
    }
  }
});
