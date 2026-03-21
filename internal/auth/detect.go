package auth

import (
	"strings"
	"time"
)

// Detection is an immutable record of an authentication challenge found in a probe response.
type Detection struct {
	Domain    string    // Target domain
	Scheme    string    // "NTLM", "Basic", "Negotiate"
	Realm     string    // Basic auth realm (may reveal internal names)
	RawHeader string    // Full WWW-Authenticate header value
	Protocol  string    // "http" or "https"
	Timestamp time.Time // When detected
}

// Detect examines a WWW-Authenticate header value and returns any auth detections.
// Returns nil if no authentication challenges found.
func Detect(domain, protocol, wwwAuth string, ts time.Time) []Detection {
	if wwwAuth == "" {
		return nil
	}

	var detections []Detection

	// WWW-Authenticate can contain multiple challenges, comma-separated
	// But NTLM/Negotiate can also contain base64 data with commas,
	// so we parse carefully by looking for known scheme names.
	schemes := parseSchemes(wwwAuth)

	for _, s := range schemes {
		det := Detection{
			Domain:    domain,
			Scheme:    s.scheme,
			Realm:     s.realm,
			RawHeader: wwwAuth,
			Protocol:  protocol,
			Timestamp: ts,
		}
		detections = append(detections, det)
	}

	return detections
}

type parsedScheme struct {
	scheme string
	realm  string
}

func parseSchemes(header string) []parsedScheme {
	var schemes []parsedScheme
	upper := strings.ToUpper(header)

	// Check for NTLM
	if strings.Contains(upper, "NTLM") {
		schemes = append(schemes, parsedScheme{scheme: "NTLM"})
	}

	// Check for Negotiate (SPNEGO — could be Kerberos or NTLM)
	if strings.Contains(upper, "NEGOTIATE") {
		schemes = append(schemes, parsedScheme{scheme: "Negotiate"})
	}

	// Check for Basic with realm extraction
	if idx := strings.Index(upper, "BASIC"); idx != -1 {
		realm := extractRealm(header[idx:])
		schemes = append(schemes, parsedScheme{scheme: "Basic", realm: realm})
	}

	// Check for Digest with realm extraction
	if idx := strings.Index(upper, "DIGEST"); idx != -1 {
		realm := extractRealm(header[idx:])
		schemes = append(schemes, parsedScheme{scheme: "Digest", realm: realm})
	}

	return schemes
}

// extractRealm extracts the realm parameter from an auth challenge.
// e.g. `Basic realm="Corporate Login"` → "Corporate Login"
func extractRealm(challenge string) string {
	lower := strings.ToLower(challenge)
	idx := strings.Index(lower, "realm=")
	if idx == -1 {
		return ""
	}

	rest := challenge[idx+6:] // Skip "realm="

	if len(rest) == 0 {
		return ""
	}

	// Handle quoted realm
	if rest[0] == '"' {
		end := strings.Index(rest[1:], "\"")
		if end == -1 {
			return rest[1:]
		}
		return rest[1 : end+1]
	}

	// Unquoted realm — ends at comma or space
	end := strings.IndexAny(rest, ", \t")
	if end == -1 {
		return rest
	}
	return rest[:end]
}
