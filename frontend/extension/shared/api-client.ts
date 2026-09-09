/**
 * API client for talking to the Go backend.
 *
 * FOR BACKEND PARTNER: this file is the complete list of every HTTP call
 * the frontend makes. There are only three functions below, matching the
 * three endpoints in API_CONTRACT.md. If you build exactly these three
 * routes with these request/response shapes, the frontend will work
 * against your server with zero changes on our side.
 *
 * The backend URL is read from one env var (see .env.example) so switching
 * between local dev and a deployed backend is a one-line change, not a
 * find-and-replace across the codebase.
 */

import type { ScanRequest, ScanResponse } from "./types";

const BACKEND_URL =
  import.meta.env.VITE_BACKEND_URL ?? "http://localhost:8080";

class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * GET /api/v1/health
 * Used by the popup to show "backend unreachable" instead of a silent
 * failure when the user tries to run an active/combined scan.
 */
export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/health`);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * POST /api/v1/scans
 * Sends passive findings already computed in the browser, plus scan mode
 * and consent. If scanMode is "active" or "combined", the backend runs the
 * active probe engine and returns the combined findings list.
 *
 * If scanMode is "passive", the backend does not need to do any probing —
 * it can just validate/store (or not store, per current no-history
 * decision) and echo the findings back, or return them unchanged.
 */
export async function submitScan(
  request: ScanRequest,
  authToken?: string,
): Promise<ScanResponse> {
  const res = await fetch(`${BACKEND_URL}/api/v1/scans`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(
      `Scan request failed: ${res.status} ${body}`,
      res.status,
    );
  }

  return res.json();
}

/**
 * GET /api/v1/scans/{scan_id}
 * Only needed if the backend responds to POST /scans with a scan_id before
 * the active probes finish (async pattern) rather than returning the full
 * result synchronously. Not used yet — wired up here so it's ready the
 * moment the backend decides which pattern to use. See the "Open question"
 * note in API_CONTRACT.md.
 */
export async function getScanResult(scanId: string): Promise<ScanResponse> {
  const res = await fetch(`${BACKEND_URL}/api/v1/scans/${scanId}`);
  if (!res.ok) {
    throw new ApiError(`Failed to fetch scan ${scanId}`, res.status);
  }
  return res.json();
}

export { ApiError };
