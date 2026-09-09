import { runContentScriptChecks } from "../lib/checks";
import type { ExtensionMessage } from "../lib/messages";

export default defineContentScript({
  matches: ["<all_urls>"],
  main() {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (
        typeof message === "object" &&
        message !== null &&
        "type" in message &&
        message.type === "REQUEST_CONTENT_FINDINGS"
      ) {
        runContentScriptChecks().then((findings) => {
          const response: ExtensionMessage = {
            type: "CONTENT_FINDINGS",
            findings,
          };
          sendResponse(response);
        });
        return true;
      }
      return true;
    });
  },
});