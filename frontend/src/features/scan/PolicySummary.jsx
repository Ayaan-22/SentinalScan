export function PolicySummary({ scan }) {
  if (!scan) return null;
  return (
    <div className="policy-summary" aria-label="Selected scan policy">
      <strong>Policy: {scan.mode || "Unrecorded (legacy / demo)"}</strong>
      <p>{scan.policy_description || "This record has no server-recorded safety policy."}</p>
      {scan.policy && <>
        <p>Scope: {scan.policy.scope_origin}</p>
        <p>Allowed: {scan.policy.allowed_endpoints.map((endpoint) => `${endpoint.methods.join(" / ")} ${endpoint.path}`).join(", ")}</p>
        <p>Excluded prefixes: {scan.policy.excluded_paths.join(", ") || "None added"}</p>
        <p>Blocked workflows: {scan.policy.sensitive_workflow_exclusions.join(", ")}</p>
        <p>Expires: {new Date(scan.policy.expires_at).toLocaleString()}</p>
        <p>Authorization: {scan.policy.policy_id} · version {scan.policy.version}</p>
        <p>Authorized by: {scan.policy.authorized_by} · {new Date(scan.policy.authorized_at).toLocaleString()}</p>
      </>}
    </div>
  );
}
