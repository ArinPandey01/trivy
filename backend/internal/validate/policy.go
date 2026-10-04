package validate

import (
	"net/url"
	"strings"

	"trivy/backend/internal/model"
)

func FilterClientFindings(input []model.Finding) []model.Finding {
	result := make([]model.Finding, 0, len(input))
	for _, incoming := range input {
		finding, keep := clientFinding(incoming)
		if keep {
			result = append(result, finding)
		}
	}
	return result
}

func FilterActiveFindings(input []model.Finding) []model.Finding {
	result := make([]model.Finding, 0, len(input))
	for _, finding := range input {
		switch finding.Category {
		case "insecure_form":
			page, pageErr := url.Parse(finding.PageURL)
			action, actionErr := url.Parse(finding.FormAction)
			if pageErr != nil || actionErr != nil || page.Scheme != "https" || action.Scheme != "http" {
				continue
			}
			finding.Severity = model.SeverityMedium
			if isTrue(finding.HasPasswordField) {
				finding.Severity = model.SeverityHigh
			}
			finding.Confidence = "likely"
			finding.Evidence = "HTTPS page contains a form whose action uses HTTP"
		case "vulnerable_library":
			finding.Severity, finding.Confidence = model.SeverityInfo, "heuristic"
			finding.KnownCVE = ""
			finding.Evidence = "script URL suggests a possibly outdated library; verify the loaded code and advisory applicability"
		case "exposed_secret":
			finding.Severity, finding.Confidence = secretRating(finding.SecretType)
			finding.Evidence = "response body matches a secret shaped pattern; validity has not been verified"
		}
		result = append(result, finding)
	}
	return result
}

func SuppressDuplicateCredentialForms(input []model.Finding) []model.Finding {
	credentials := make(map[string]bool)
	for _, finding := range input {
		if finding.Category == "unencrypted_credentials" {
			credentials[formKey(finding)] = true
		}
	}
	result := make([]model.Finding, 0, len(input))
	for _, finding := range input {
		if finding.Category == "insecure_form" && isTrue(finding.HasPasswordField) && credentials[formKey(finding)] {
			continue
		}
		result = append(result, finding)
	}
	return result
}

func formKey(finding model.Finding) string {
	return strings.ToLower(finding.PageURL) + "\x00" + strings.ToLower(finding.FormAction)
}

func secretRating(secretType string) (model.Severity, string) {
	switch secretType {
	case "private_key_block", "private_key", "aws_access_key", "stripe_key":
		return model.SeverityHigh, "heuristic"
	default:
		return model.SeverityInfo, "heuristic"
	}
}

func clientFinding(in model.Finding) (model.Finding, bool) {
	f := model.Finding{
		Category: in.Category, PageURL: in.PageURL, Source: "extension",
	}
	page, _ := url.Parse(in.PageURL)
	switch in.Category {
	case "header":
		if in.Status == "ok" || in.Header == "access-control-allow-origin" {
			return f, false
		}
		if in.Header == "strict-transport-security" && page.Scheme != "https" {
			return f, false
		}
		f.Header, f.Status = in.Header, in.Status
		if in.Value != nil {
			redacted := "[redacted]"
			f.Value = &redacted
		}
		f.Severity, f.Confidence = headerSeverity(in.Header, in.Status), "heuristic"
		f.Evidence = "browser reported a missing or weak response header"
	case "insecure_form":
		action, _ := url.Parse(in.FormAction)
		if page.Scheme != "https" || action.Scheme != "http" {
			return f, false
		}
		f.FormAction, f.Method = in.FormAction, in.Method
		f.HasPasswordField, f.IsActionInsecure = in.HasPasswordField, boolPolicy(true)
		f.AutocompleteOnSensitive, f.HasCSRFToken = in.AutocompleteOnSensitive, in.HasCSRFToken
		f.Severity, f.Confidence = model.SeverityMedium, "likely"
		if isTrue(in.HasPasswordField) {
			f.Severity = model.SeverityHigh
		}
		f.Evidence = "HTTPS page contains a form whose action uses HTTP"
	case "unencrypted_credentials":
		f.FormAction, f.HasPasswordField, f.IsHTTP = in.FormAction, boolPolicy(true), boolPolicy(true)
		f.Severity, f.Confidence = model.SeverityHigh, "likely"
		f.Evidence = "password form action uses HTTP"
	case "mixed_content":
		f.ResourceURL, f.ResourceType = in.ResourceURL, in.ResourceType
		f.Severity, f.Confidence = model.SeverityLow, "likely"
		if in.ResourceType == "script" || in.ResourceType == "iframe" {
			f.Severity = model.SeverityHigh
		}
		f.Evidence = "HTTPS page references an HTTP resource"
	case "sensitive_url":
		f.URL, f.ParameterName, f.MatchReason = in.URL, in.ParameterName, "parameter name suggests sensitive data"
		f.Severity, f.Confidence = model.SeverityMedium, "heuristic"
		f.Evidence = "parameter name suggests sensitive data in a URL; value was redacted"
	case "insecure_cookie":
		f.CookieName = in.CookieName
		f.MissingSecure, f.MissingHTTPOnly, f.MissingSameSite = in.MissingSecure, in.MissingHTTPOnly, in.MissingSameSite
		f.Severity, f.Confidence = cookieSeverity(in.CookieName, isTrue(in.MissingSecure), isTrue(in.MissingHTTPOnly), isTrue(in.MissingSameSite)), "heuristic"
		f.Evidence = "browser reported missing cookie attributes"
	case "exposed_secret":
		f.SecretType, f.Location = in.SecretType, "browser page"
		f.Severity, f.Confidence = secretRating(in.SecretType)
		f.Evidence = "browser found a secret shaped pattern; validity has not been verified"
	case "vulnerable_library":
		f.LibraryName, f.DetectedVersion = in.LibraryName, in.DetectedVersion
		f.Severity, f.Confidence = model.SeverityInfo, "heuristic"
		f.Evidence = "browser reported a possibly outdated library version; verify the loaded code and advisory applicability"
	case "sensitive_storage":
		f.StorageType, f.KeyName, f.Reason = in.StorageType, "[redacted]", "storage entry matched a sensitive-data heuristic"
		f.Severity, f.Confidence = model.SeverityInfo, "heuristic"
		f.Evidence = "browser storage entry may contain sensitive data; value was not sent"
	default:
		return f, false
	}
	return f, true
}

func boolPolicy(value bool) *bool { return &value }
