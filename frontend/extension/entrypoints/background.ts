import { evaluateHeaders } from "../lib/checks/headers";
import { evaluateCookies } from "../lib/checks/cookies";
import { getCachedHeaders, setCachedHeaders } from "../lib/headerCache";
import { isExtensionMessage, type ExtensionMessage } from "../lib/messages";
import { loadSettings } from "../lib/settings";
import { checkHealth, submitScan } from "../shared/api-client";
import type { Finding, ScanMode, ScanResponse } from "../shared/types";

export default defineBackground(() => {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.type !== "main_frame" || !details.responseHeaders) return;
      setCachedHeaders(details.tabId, {
        pageUrl: details.url,
        headers: details.responseHeaders.map((h) => ({
          name: h.name,
          value: h.value ?? "",
        })),
      });
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"],
  );

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!isExtensionMessage(message)) return false;

    if (message.type === "RUN_SCAN") {
      runScan(message.scanMode, message.consent, sender.tab?.id)
        .then((result) => sendResponse({ type: "SCAN_COMPLETE", result }))
        .catch((err: Error) =>
          sendResponse({ type: "SCAN_ERROR", message: err.message }),
        );
      return true;
    }

    return false;
  });
});

function reportProgress(percent: number): void {
  const message: ExtensionMessage = { type: "SCAN_PROGRESS", percent };
  chrome.runtime.sendMessage(message).catch(() => {});
}

async function runScan(
  scanMode: ScanMode,
  consent: boolean,
  tabId: number | undefined,
): Promise<ScanResponse> {
  const settings = await loadSettings();

  const [activeTab] = await chrome.tabs.query({
    active: true,
    currentWindow: true,
  });
  const targetTabId = tabId ?? activeTab?.id;
  if (targetTabId === undefined || !activeTab?.url) {
    throw new Error("No active tab found to scan.");
  }

  reportProgress(10);

  const contentResponse = (await chrome.tabs.sendMessage(targetTabId, {
    type: "REQUEST_CONTENT_FINDINGS",
  })) as ExtensionMessage;
  const contentFindings: Finding[] =
    contentResponse.type === "CONTENT_FINDINGS" ? contentResponse.findings : [];

  reportProgress(45);

  const cached = getCachedHeaders(targetTabId);
  const headerFindings =
    settings.enabledCategories.header !== false && cached && cached.pageUrl === activeTab.url
      ? evaluateHeaders(cached.pageUrl, cached.headers)
      : [];

  reportProgress(60);

  const cookieFindings =
    settings.enabledCategories.insecure_cookie !== false
      ? evaluateCookies(
          activeTab.url,
          (await chrome.cookies.getAll({ url: activeTab.url })).map((c) => ({
            name: c.name,
            secure: c.secure,
            httpOnly: c.httpOnly,
            sameSite: c.sameSite,
          })),
        )
      : [];

  reportProgress(75);

  const passiveFindings: Finding[] = [
    ...contentFindings,
    ...headerFindings,
    ...cookieFindings,
  ];

  if (scanMode === "passive") {
    reportProgress(100);
    return { findings: passiveFindings };
  }

  if (!consent) {
    throw new Error("Consent is required for active or combined scans.");
  }

  const currentPath = new URL(activeTab.url).pathname;
  const isExcludedPath = settings.excludedPaths.some((p) => currentPath.startsWith(p));
  if (isExcludedPath) {
    throw new Error(
      `This path (${currentPath}) is excluded from active scanning in your settings.`,
    );
  }

  reportProgress(85);

  const backendUp = await checkHealth();
  if (!backendUp) {
    throw new Error("Backend is unreachable. Try again shortly.");
  }

  const result = await submitScan({
    target: activeTab.url,
    scanMode,
    consent,
    findings: passiveFindings,
    rateLimit: {
      requestsPerSecond: settings.requestsPerSecond,
      maxConcurrency: settings.maxConcurrency,
    },
    excludedPaths: settings.excludedPaths,
  });

  reportProgress(100);
  return result;
}