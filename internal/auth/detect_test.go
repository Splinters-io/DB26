package auth

import (
	"testing"
	"time"
)

func TestDetectNTLM(t *testing.T) {
	ts := time.Now()
	dets := Detect("corp.example.com", "http", "NTLM", ts)

	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if dets[0].Scheme != "NTLM" {
		t.Errorf("scheme = %q, want NTLM", dets[0].Scheme)
	}
	if dets[0].Domain != "corp.example.com" {
		t.Errorf("domain = %q, want corp.example.com", dets[0].Domain)
	}
}

func TestDetectNegotiate(t *testing.T) {
	ts := time.Now()
	dets := Detect("vpn.example.com", "https", "Negotiate", ts)

	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if dets[0].Scheme != "Negotiate" {
		t.Errorf("scheme = %q, want Negotiate", dets[0].Scheme)
	}
}

func TestDetectBasicWithRealm(t *testing.T) {
	ts := time.Now()
	dets := Detect("mail.example.com", "http", `Basic realm="Corporate Mail"`, ts)

	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if dets[0].Scheme != "Basic" {
		t.Errorf("scheme = %q, want Basic", dets[0].Scheme)
	}
	if dets[0].Realm != "Corporate Mail" {
		t.Errorf("realm = %q, want 'Corporate Mail'", dets[0].Realm)
	}
}

func TestDetectMultipleSchemes(t *testing.T) {
	ts := time.Now()
	// Some servers return both NTLM and Negotiate
	dets := Detect("dc.example.com", "http", "Negotiate, NTLM", ts)

	if len(dets) != 2 {
		t.Fatalf("expected 2 detections, got %d", len(dets))
	}

	schemes := make(map[string]bool)
	for _, d := range dets {
		schemes[d.Scheme] = true
	}
	if !schemes["NTLM"] {
		t.Error("missing NTLM detection")
	}
	if !schemes["Negotiate"] {
		t.Error("missing Negotiate detection")
	}
}

func TestDetectEmpty(t *testing.T) {
	ts := time.Now()
	dets := Detect("example.com", "http", "", ts)

	if dets != nil {
		t.Errorf("expected nil, got %d detections", len(dets))
	}
}

func TestDetectDigest(t *testing.T) {
	ts := time.Now()
	dets := Detect("example.com", "http", `Digest realm="admin@example.com", nonce="abc123"`, ts)

	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
	if dets[0].Scheme != "Digest" {
		t.Errorf("scheme = %q, want Digest", dets[0].Scheme)
	}
	if dets[0].Realm != "admin@example.com" {
		t.Errorf("realm = %q, want admin@example.com", dets[0].Realm)
	}
}

func TestExtractRealm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"quoted", `Basic realm="My Realm"`, "My Realm"},
		{"unquoted", `Basic realm=MyRealm`, "MyRealm"},
		{"with trailing", `Basic realm="Corp" charset="UTF-8"`, "Corp"},
		{"no realm", `Basic`, ""},
		{"empty realm", `Basic realm=""`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRealm(tt.input)
			if got != tt.expected {
				t.Errorf("extractRealm(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
