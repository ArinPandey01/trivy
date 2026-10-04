package validate

import (
	"testing"

	"trivy/backend/internal/model"
)

func TestFilterClientFindings(t *testing.T) {
	falseValue, trueValue := false, true
	tests := []struct {
		name     string
		finding  model.Finding
		wantKeep bool
		severity model.Severity
	}{
		{"missing CSRF alone", model.Finding{Category: "insecure_form", PageURL: "https://example.com/", FormAction: "https://example.com/login", Method: "POST", HasPasswordField: &falseValue, IsActionInsecure: &falseValue, AutocompleteOnSensitive: &falseValue, HasCSRFToken: &falseValue, Severity: model.SeverityCritical}, false, ""},
		{"HTTP form action", model.Finding{Category: "insecure_form", PageURL: "https://example.com/", FormAction: "http://example.com/login", Method: "POST", HasPasswordField: &falseValue, IsActionInsecure: &trueValue, AutocompleteOnSensitive: &falseValue, HasCSRFToken: &falseValue, Severity: model.SeverityLow}, true, model.SeverityMedium},
		{"HSTS on HTTP", model.Finding{Category: "header", PageURL: "http://example.com/", Header: "strict-transport-security", Status: "missing", Severity: model.SeverityHigh}, false, ""},
		{"wildcard CORS header alone", model.Finding{Category: "header", PageURL: "https://example.com/", Header: "access-control-allow-origin", Status: "weak", Severity: model.SeverityHigh}, false, ""},
		{"library is review item", model.Finding{Category: "vulnerable_library", PageURL: "https://example.com/", LibraryName: "jQuery", DetectedVersion: "3.4.1", KnownCVE: "CVE-2020-11022", Severity: model.SeverityHigh}, true, model.SeverityInfo},
		{"mixed script", model.Finding{Category: "mixed_content", PageURL: "https://example.com/", ResourceURL: "http://cdn.example.com/a.js", ResourceType: "script", Severity: model.SeverityInfo}, true, model.SeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Finding(&tt.finding); err != nil {
				t.Fatal(err)
			}
			got := FilterClientFindings([]model.Finding{tt.finding})
			if len(got) != 0 && !tt.wantKeep || len(got) != 1 && tt.wantKeep {
				t.Fatalf("findings = %#v, want keep %v", got, tt.wantKeep)
			}
			if !tt.wantKeep {
				return
			}
			if got[0].Severity != tt.severity || got[0].Source != "extension" || got[0].Confidence == "" {
				t.Fatalf("policy finding = %#v", got[0])
			}
			if got[0].KnownCVE != "" || got[0].Evidence == "" {
				t.Fatalf("client metadata was retained or evidence missing: %#v", got[0])
			}
		})
	}
}

func TestRequestRejectsFindingFromDifferentOrigin(t *testing.T) {
	req := model.ScanRequest{Target: "https://example.com/", ScanMode: "passive", Findings: []model.Finding{{Category: "header", PageURL: "https://other.example/", Header: "content-security-policy", Status: "missing", Severity: model.SeverityMedium}}}
	if _, err := Request(&req, 10, 5); err == nil {
		t.Fatal("expected a page origin validation error")
	}
}

func TestFilterActiveFindingsUsesCautiousRatings(t *testing.T) {
	input := []model.Finding{
		{Category: "vulnerable_library", PageURL: "https://example.com/", LibraryName: "jQuery", DetectedVersion: "3.4.1", KnownCVE: "CVE-2020-11022", Severity: model.SeverityHigh, Source: "http"},
		{Category: "exposed_secret", PageURL: "https://example.com/", SecretType: "jwt", Severity: model.SeverityHigh, Source: "http"},
		{Category: "insecure_form", PageURL: "https://example.com/", FormAction: "https://example.com/login", Severity: model.SeverityMedium, Source: "http"},
	}
	got := FilterActiveFindings(input)
	if len(got) != 2 || got[0].Severity != model.SeverityInfo || got[0].KnownCVE != "" || got[1].Severity != model.SeverityInfo {
		t.Fatalf("active findings = %#v", got)
	}
	browser := FilterClientFindings([]model.Finding{{Category: "vulnerable_library", PageURL: "https://example.com/", LibraryName: "jQuery", DetectedVersion: "3.4.1", Severity: model.SeverityHigh}})
	if got := len(Deduplicate(append(got, browser...))); got != 2 {
		t.Fatalf("deduplicated finding count = %d, want 2", got)
	}
}

func TestSuppressDuplicateCredentialForms(t *testing.T) {
	password := true
	findings := []model.Finding{
		{Category: "insecure_form", PageURL: "https://example.com/", FormAction: "http://example.com/login", HasPasswordField: &password},
		{Category: "unencrypted_credentials", PageURL: "https://example.com/", FormAction: "http://example.com/login"},
	}
	got := SuppressDuplicateCredentialForms(findings)
	if len(got) != 1 || got[0].Category != "unencrypted_credentials" {
		t.Fatalf("findings = %#v, want only credential finding", got)
	}
}

func TestClientPolicyDropsUntrustedDescriptions(t *testing.T) {
	secret := "do-not-store-this-secret"
	findings := FilterClientFindings([]model.Finding{
		{Category: "sensitive_url", PageURL: "https://example.com/", URL: "https://example.com/?token=***", ParameterName: "token", MatchReason: secret},
		{Category: "exposed_secret", PageURL: "https://example.com/", SecretType: "jwt", Location: secret},
		{Category: "sensitive_storage", PageURL: "https://example.com/", StorageType: "localStorage", KeyName: secret, Reason: secret},
	})
	if len(findings) != 3 {
		t.Fatalf("findings = %#v", findings)
	}
	for _, finding := range findings {
		if finding.MatchReason == secret || finding.Location == secret || finding.KeyName == secret || finding.Reason == secret {
			t.Fatalf("untrusted text retained: %#v", finding)
		}
	}
}
