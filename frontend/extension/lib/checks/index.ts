import type { Finding } from "../../shared/types";
import { loadSettings } from "../settings";
import { checkForms } from "./forms";
import { checkMixedContent } from "./mixedContent";
import { checkSensitiveUrl } from "./sensitiveUrl";
import { checkExposedSecrets } from "./secrets";
import { checkVulnerableLibraries } from "./libraries";
import { checkSensitiveStorage } from "./storage";

export async function runContentScriptChecks(): Promise<Finding[]> {
  const settings = await loadSettings();

  const { insecureForms, credentialFindings } = checkForms();
  const mixedContent = checkMixedContent();
  const sensitiveUrls = checkSensitiveUrl();
  const secrets = checkExposedSecrets();
  const libraries = checkVulnerableLibraries();
  const storage = checkSensitiveStorage();

  const all: Finding[] = [
    ...insecureForms,
    ...credentialFindings,
    ...mixedContent,
    ...sensitiveUrls,
    ...secrets,
    ...libraries,
    ...storage,
  ];

  return all.filter((f) => settings.enabledCategories[f.category] !== false);
}