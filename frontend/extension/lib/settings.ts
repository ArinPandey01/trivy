import { DEFAULT_SETTINGS, type ScanSettings } from "../shared/types";

export const SETTINGS_STORAGE_KEY = "scanSettings";

export function loadSettings(): Promise<ScanSettings> {
  return new Promise((resolve) => {
    chrome.storage.local.get([SETTINGS_STORAGE_KEY], (result) => {
      resolve({ ...DEFAULT_SETTINGS, ...(result[SETTINGS_STORAGE_KEY] ?? {}) });
    });
  });
}

export function saveSettings(settings: ScanSettings): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: settings }, () => resolve());
  });
}