export function buildPolicy(config, excludedPaths = []) {
  const grants = new Map();
  for (const line of config.allowed_endpoints_str.split(/\r?\n/).filter((line) => line.trim())) {
    const match = line.trim().match(/^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+(\/\S*)$/);
    if (!match) throw new Error("Enter one exact permission per line, such as GET /search.");
    const [, method, path] = match;
    grants.set(path, [...new Set([...(grants.get(path) || []), method])]);
  }
  if (!grants.size) throw new Error("Add at least one endpoint permission, including GET for the target page.");
  return {
    mode: config.mode,
    scope_origin: new URL(config.target_url).origin,
    allowed_endpoints: [...grants].map(([path, methods]) => ({ path, methods })),
    excluded_paths: excludedPaths,
    expires_at: new Date(config.policy_expires_at).toISOString(),
    authorization_confirmed: config.authorization_confirmed === true,
  };
}

export function capturedPages(config) {
  if (!config.captured_content) throw new Error("Paste captured HTML for passive analysis. Passive mode makes no target requests.");
  return [{
    url: config.target_url,
    content: config.captured_content,
    headers: config.captured_headers.trim() ? JSON.parse(config.captured_headers) : null,
  }];
}
