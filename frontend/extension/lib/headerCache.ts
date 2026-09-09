export interface CachedHeaders {
  pageUrl: string;
  headers: { name: string; value: string }[];
}

const headerCacheByTab = new Map<number, CachedHeaders>();

export function setCachedHeaders(tabId: number, data: CachedHeaders): void {
  headerCacheByTab.set(tabId, data);
}

export function getCachedHeaders(tabId: number): CachedHeaders | undefined {
  return headerCacheByTab.get(tabId);
}