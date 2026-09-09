import { useState } from "react";
import { submitScan } from "./shared/api-client";
import type { Finding } from "./shared/types";
import { describeFinding, getRemediation } from "./lib/remediation";

type ScanState = "idle" | "running" | "done" | "error";

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

function severityCounts(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity === "Critical") counts.critical++;
    else if (f.severity === "High") counts.high++;
    else if (f.severity === "Medium") counts.medium++;
    else if (f.severity === "Low") counts.low++;
  }
  return counts;
}

export default function App() {
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState(0);

  const counts = severityCounts(findings);

  async function runScan() {
    if (!consent) return;
    setScanState("running");
    setErrorMessage(null);

    try {
      // Website can't produce passive findings itself (no DOM access to a
      // third-party page) — this always runs as an active-only scan, so
      // `findings` starts empty; whatever comes back is entirely from the
      // backend's active probe engine.
      const result = await submitScan({
        target,
        scanMode: "active",
        consent,
        findings: [],
      });
      const sorted = [...result.findings].sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      );
      setFindings(sorted);
      setSelected(0);
      setScanState("done");
    } catch (err) {
      setScanState("error");
      setErrorMessage(err instanceof Error ? err.message : "Scan failed.");
    }
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(findings, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trivy-scan-${safeDomain(target)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const selectedFinding = findings[selected];

  return (
    <main className="dashboard">
      <header className="dashboard__header">
        <span className="dashboard__title">Trivy</span>
        <span className="dashboard__subtitle">Dashboard — active scan</span>
      </header>

      <section className="glass-panel scan-form">
        <input
          type="url"
          placeholder="https://example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="target-input"
        />
        <label className="consent">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
          />
          I'm authorized to run active security tests against this domain
        </label>
        <button
          type="button"
          className="run-button"
          disabled={scanState === "running" || !consent || !target}
          onClick={runScan}
        >
          {scanState === "running" ? "Scanning…" : "▶ Run active scan"}
        </button>
        {errorMessage && <p className="error-text">{errorMessage}</p>}
      </section>

      {scanState === "done" && (
        <>
          <section className="summary-cards">
            <div className="summary-card summary-card--critical">
              <span className="summary-card__num">{counts.critical}</span>
              <span className="summary-card__label">Critical</span>
            </div>
            <div className="summary-card summary-card--high">
              <span className="summary-card__num">{counts.high}</span>
              <span className="summary-card__label">High</span>
            </div>
            <div className="summary-card summary-card--medium">
              <span className="summary-card__num">{counts.medium}</span>
              <span className="summary-card__label">Medium</span>
            </div>
            <div className="summary-card summary-card--low">
              <span className="summary-card__num">{counts.low}</span>
              <span className="summary-card__label">Low</span>
            </div>
          </section>

          <section className="results-panel">
            <div className="glass-panel findings-column">
              <div className="findings-column__header">
                <h2>Findings ({findings.length})</h2>
                <button type="button" onClick={exportJson}>⬇ Export JSON</button>
              </div>
              {findings.length === 0 ? (
                <p className="empty-state">No issues found for this target.</p>
              ) : (
                <ul className="findings-list">
                  {findings.map((f, i) => {
                    const { title } = describeFinding(f);
                    return (
                      <li
                        key={i}
                        className={`finding finding--${f.severity.toLowerCase()} ${i === selected ? "finding--selected" : ""}`}
                        onClick={() => setSelected(i)}
                      >
                        <span className="finding__dot" />
                        <span className="finding__label">{title}</span>
                        <span className="finding__severity">{f.severity}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {selectedFinding && (
              <div className="glass-panel detail-panel">
                <DetailView finding={selectedFinding} />
              </div>
            )}
          </section>
        </>
      )}
    </main>
  );
}

function DetailView({ finding }: { finding: Finding }) {
  const { title, evidence } = describeFinding(finding);
  const { remediation, references } = getRemediation(finding.category);

  return (
    <>
      <div className="detail-panel__header">
        <h3>{title}</h3>
        <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </span>
      </div>
      <p className="detail-panel__meta">{finding.pageUrl} · {finding.category}</p>

      <h4>Evidence</h4>
      <div className="evidence-block">{evidence}</div>

      <h4>Fix</h4>
      <p className="detail-panel__fix">{remediation}</p>

      <p className="detail-panel__refs">refs: {references}</p>
    </>
  );
}

function safeDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "scan";
  }
}
