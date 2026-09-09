import type {
  InsecureFormFinding,
  UnencryptedCredentialsFinding,
} from "../../shared/types";

const SENSITIVE_AUTOCOMPLETE_TYPES = new Set([
  "password",
  "cc-number",
  "cc-csc",
  "cc-exp",
]);

/**
 * Scans every <form> on the current page for insecure configuration.
 * Returns two separate finding types since "insecure form" (Medium) and
 * "unencrypted credential submission" (High) are reported as distinct
 * findings even though they're detected from the same form element.
 */
export function checkForms(): {
  insecureForms: InsecureFormFinding[];
  credentialFindings: UnencryptedCredentialsFinding[];
} {
  const pageUrl = window.location.href;
  const insecureForms: InsecureFormFinding[] = [];
  const credentialFindings: UnencryptedCredentialsFinding[] = [];

  const forms = Array.from(document.querySelectorAll("form"));

  for (const form of forms) {
    const actionAttr = form.getAttribute("action") ?? window.location.href;
    // Resolve relative action URLs against the current page.
    const actionUrl = new URL(actionAttr, window.location.href).href;
    const isActionInsecure = actionUrl.startsWith("http://");

    const passwordInput = form.querySelector<HTMLInputElement>(
      'input[type="password"]',
    );
    const hasPasswordField = passwordInput !== null;

    const autocompleteOnSensitive = Array.from(
      form.querySelectorAll<HTMLInputElement>("input"),
    ).some((input) => {
      const type = (input.getAttribute("autocomplete") ?? "").toLowerCase();
      return (
        SENSITIVE_AUTOCOMPLETE_TYPES.has(input.type) &&
        input.autocomplete !== "off" &&
        !type.includes("off")
      );
    });

    // Heuristic only, per the report's "limitations of findings" note —
    // this is a signal, not proof a CSRF token is actually missing.
    const hasCsrfToken =
      form.querySelector('input[name*="csrf" i], input[name*="token" i]') !==
      null;

    const method = (
      form.getAttribute("method")?.toUpperCase() === "POST" ? "POST" : "GET"
    ) as "GET" | "POST";

    if (isActionInsecure || autocompleteOnSensitive || !hasCsrfToken) {
      insecureForms.push({
        category: "insecure_form",
        pageUrl,
        formAction: actionUrl,
        method,
        hasPasswordField,
        isActionInsecure,
        autocompleteOnSensitive,
        hasCsrfToken,
        severity: isActionInsecure && hasPasswordField ? "High" : "Medium",
      });
    }

    if (hasPasswordField && isActionInsecure) {
      credentialFindings.push({
        category: "unencrypted_credentials",
        pageUrl,
        formAction: actionUrl,
        hasPasswordField: true,
        isHttp: true,
        severity: "High",
      });
    }
  }

  return { insecureForms, credentialFindings };
}
