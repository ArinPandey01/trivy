import type { MixedContentFinding } from "../../shared/types";

const HIGH_RISK_TAGS = new Set(["SCRIPT", "IFRAME"]);

const RESOURCE_SELECTORS: { selector: string; attr: string }[] = [
  { selector: "script[src]", attr: "src" },
  { selector: "img[src]", attr: "src" },
  { selector: "link[rel='stylesheet'][href]", attr: "href" },
  { selector: "iframe[src]", attr: "src" },
];

function resourceTypeFor(tagName: string): MixedContentFinding["resourceType"] {
  switch (tagName) {
    case "SCRIPT":
      return "script";
    case "IFRAME":
      return "iframe";
    case "LINK":
      return "stylesheet";
    default:
      return "image";
  }
}

/**
 * Only meaningful when the page itself is HTTPS — an HTTP page loading
 * HTTP resources isn't "mixed" content, it's just an insecure page (and
 * that's already covered by other checks).
 */
export function checkMixedContent(): MixedContentFinding[] {
  const pageUrl = window.location.href;
  if (window.location.protocol !== "https:") return [];

  const findings: MixedContentFinding[] = [];
  const seen = new Set<string>(); // dedupe repeated resources

  for (const { selector, attr } of RESOURCE_SELECTORS) {
    const elements = document.querySelectorAll(selector);
    elements.forEach((el) => {
      const raw = el.getAttribute(attr);
      if (!raw) return;
      let resolved: string;
      try {
        resolved = new URL(raw, pageUrl).href;
      } catch {
        return;
      }
      if (!resolved.startsWith("http://")) return;
      if (seen.has(resolved)) return;
      seen.add(resolved);

      const resourceType = resourceTypeFor(el.tagName);
      findings.push({
        category: "mixed_content",
        pageUrl,
        resourceUrl: resolved,
        resourceType,
        severity: HIGH_RISK_TAGS.has(el.tagName) ? "High" : "Low",
      });
    });
  }

  return findings;
}
