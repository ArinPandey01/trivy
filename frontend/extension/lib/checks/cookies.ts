import type { InsecureCookieFinding } from "../../shared/types";

export function evaluateCookies(
  pageUrl: string,
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[],
): InsecureCookieFinding[] {
  const findings: InsecureCookieFinding[] = [];

  for (const cookie of cookies) {
    const missingSecure = !cookie.secure;
    const missingHttpOnly = !cookie.httpOnly;
    const missingSameSite =
      !cookie.sameSite || cookie.sameSite.toLowerCase() === "no_restriction";

    if (!missingSecure && !missingHttpOnly && !missingSameSite) continue;

    const severity = missingSecure && missingHttpOnly ? "High" : "Medium";

    findings.push({
      category: "insecure_cookie",
      pageUrl,
      cookieName: cookie.name,
      missingSecure,
      missingHttpOnly,
      missingSameSite,
      severity,
    });
  }

  return findings;
}