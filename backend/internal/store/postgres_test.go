package store

import (
	"testing"

	"trivy/backend/internal/model"
)

func TestSanitizeResponseDoesNotMutateInput(t *testing.T) {
	original := model.ScanResponse{Findings: []model.Finding{{
		PageURL:         "https://example.com/private/secret?token=secret#/token",
		SampleURLs:      []string{"https://example.com/a?key=secret"},
		EvidenceSnippet: "database error and secret token",
		Value:           stringTestValue("private header value"),
	}}}
	got := SanitizeResponse(original)
	if original.Findings[0].SampleURLs[0] != "https://example.com/a?key=secret" {
		t.Fatal("sanitization mutated the original sample URLs")
	}
	if got.Findings[0].PageURL == original.Findings[0].PageURL || got.Findings[0].SampleURLs[0] == original.Findings[0].SampleURLs[0] {
		t.Fatalf("sensitive URL was not sanitized: %#v", got.Findings[0])
	}
	if got.Findings[0].PageURL != "https://example.com/redacted" || got.Findings[0].EvidenceSnippet != "[redacted]" || *got.Findings[0].Value != "[redacted]" {
		t.Fatalf("private path or evidence was retained: %#v", got.Findings[0])
	}
}

func stringTestValue(value string) *string { return &value }
