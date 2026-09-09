import type { ExposedSecretFinding } from "../../shared/types";

const SECRET_PATTERNS: { type: string; pattern: RegExp }[] = [
  { type: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/ },
  { type: "google_api_key", pattern: /AIza[0-9A-Za-z\-_]{35}/ },
  { type: "jwt", pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
  { type: "stripe_key", pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  { type: "generic_api_key", pattern: /(?:api[_-]?key|apikey)["']?\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/i },
  { type: "private_key_block", pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
];

const MAX_MATCHES_PER_PAGE = 25;

export function checkExposedSecrets(): ExposedSecretFinding[] {
  const pageUrl = window.location.href;
  const findings: ExposedSecretFinding[] = [];
  const scripts = Array.from(document.querySelectorAll("script:not([src])"));

  let matchCount = 0;
  for (const script of scripts) {
    if (matchCount >= MAX_MATCHES_PER_PAGE) break;
    const text = script.textContent ?? "";
    if (!text) continue;

    for (const { type, pattern } of SECRET_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({
          category: "exposed_secret",
          pageUrl,
          secretType: type,
          location: "inline <script> tag",
          severity: "High",
        });
        matchCount++;
        if (matchCount >= MAX_MATCHES_PER_PAGE) break;
      }
    }
  }

  return findings;
}