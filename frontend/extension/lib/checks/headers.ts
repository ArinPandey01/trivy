import type { HeaderFinding, Severity } from "../../shared/types";

interface HeaderRule {
  name: string;
  severityIfMissing: Severity;
  /** Optional: flag as "weak" rather than "missing" if present but bad. */
  isWeak?: (value: string) => boolean;
}

const HEADER_RULES: HeaderRule[] = [
  { name: "content-security-policy", severityIfMissing: "Medium" },
  { name: "strict-transport-security", severityIfMissing: "Medium" },
  { name: "x-frame-options", severityIfMissing: "Medium" },
  { name: "x-content-type-options", severityIfMissing: "Low" },
  { name: "referrer-policy", severityIfMissing: "Low" },
  {
    name: "permissions-policy",
    severityIfMissing: "Low",
  },
  {
    name: "access-control-allow-origin",
    severityIfMissing: "Info", // absence is fine; presence is checked for being risky below
    isWeak: (value) => value.trim() === "*",
  },
];

/**
 * Pure function: given the raw response headers for the main document
 * request, returns a HeaderFinding for every header that's missing or
 * weak. Called from background.ts, which is the only place with access
 * to raw response headers via the webRequest API.
 */
export function evaluateHeaders(
  pageUrl: string,
  headers: { name: string; value: string }[],
): HeaderFinding[] {
  const lookup = new Map(
    headers.map((h) => [h.name.toLowerCase(), h.value]),
  );
  const findings: HeaderFinding[] = [];

  for (const rule of HEADER_RULES) {
    const value = lookup.get(rule.name);

    if (value === undefined) {
      // Skip reporting "missing" for headers where absence is the safe
      // default (e.g. no CORS header at all is fine).
      if (rule.severityIfMissing === "Info") continue;
      findings.push({
        category: "header",
        pageUrl,
        header: rule.name,
        value: null,
        status: "missing",
        severity: rule.severityIfMissing,
      });
      continue;
    }

    if (rule.isWeak?.(value)) {
      findings.push({
        category: "header",
        pageUrl,
        header: rule.name,
        value,
        status: "weak",
        severity: "High",
      });
    }
  }

  return findings;
}
