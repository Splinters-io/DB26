package headers

import (
	"strings"
	"testing"
)

func TestCleanDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple domain", "example.com", "example.com"},
		{"subdomain", "www.example.com", "www.example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"with protocol", "https://example.com", "example.com"},
		{"with path", "example.com/path", "example.com"},
		{"with port", "example.com:8080", "example.com"},
		{"already clean", "example", "example"},
		{"ip address", "192.168.1.1", "192.168.1.1"},
		{"hyphenated domain", "my-site.com", "my-site.com"},
		{"hyphen + subdomain", "sub.my-app.co.uk", "sub.my-app.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanDomain(tt.input)
			if got != tt.expected {
				t.Errorf("CleanDomain(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuild(t *testing.T) {
	payloads := Build("example.com", "abc123.oob.example.com")

	if len(payloads) != 15 {
		t.Errorf("Build returned %d payloads, want 15", len(payloads))
	}

	for _, p := range payloads {
		if p.Name == "" {
			t.Error("payload has empty Name")
		}
		if p.Value == "" {
			t.Errorf("payload %s has empty Value", p.Name)
		}
	}

	// Dots preserved in domain — no sanitization
	foundXFF := false
	foundHost := false
	for _, p := range payloads {
		if p.Name == "X-Forwarded-For" {
			foundXFF = true
			if !strings.Contains(p.Value, "xff.example.com.abc123.oob.example.com") {
				t.Errorf("XFF value = %q, want to contain xff.example.com.abc123", p.Value)
			}
		}
		if p.Name == "Host" {
			foundHost = true
			if !strings.Contains(p.Value, "host.example.com.abc123.oob.example.com") {
				t.Errorf("Host value = %q, want to contain host.example.com.abc123", p.Value)
			}
		}
	}

	if !foundXFF {
		t.Error("X-Forwarded-For not found")
	}
	if !foundHost {
		t.Error("Host not found")
	}
}

func TestBuildHyphenatedDomain(t *testing.T) {
	payloads := Build("my-site.co.uk", "oob.example.com")

	for _, p := range payloads {
		if p.Name == "X-Forwarded-For" {
			// Hyphens preserved, dots preserved
			if !strings.Contains(p.Value, "xff.my-site.co.uk.oob.example.com") {
				t.Errorf("XFF = %q, want xff.my-site.co.uk.oob.example.com", p.Value)
			}
		}
	}
}

func TestBuildFormats(t *testing.T) {
	payloads := Build("test.org", "oob.example.com")
	payloadMap := make(map[string]string)
	for _, p := range payloads {
		payloadMap[p.Name] = p.Value
	}

	wafp := payloadMap["X-Wap-Profile"]
	if !strings.HasPrefix(wafp, "http://") || !strings.HasSuffix(wafp, "/wap.xml") {
		t.Errorf("X-Wap-Profile = %q, want http://...wafp.test.org.oob.../wap.xml", wafp)
	}

	contact := payloadMap["Contact"]
	if !strings.HasPrefix(contact, "root@") {
		t.Errorf("Contact = %q, want root@...", contact)
	}

	fwd := payloadMap["Forwarded"]
	if !strings.HasPrefix(fwd, "for=") {
		t.Errorf("Forwarded = %q, want for=...", fwd)
	}

	origin := payloadMap["Origin"]
	if !strings.HasPrefix(origin, "https://") {
		t.Errorf("Origin = %q, want https://...", origin)
	}
}

func TestIsValidDNSName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"normal", "xff.example.com.oob.example.com", true},
		{"too long label", strings.Repeat("a", 64) + ".com", false},
		{"empty label", "xff..oob.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidDNSName(tt.input)
			if got != tt.valid {
				t.Errorf("isValidDNSName(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}
