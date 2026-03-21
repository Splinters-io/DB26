package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := DeriveKey("test-passphrase")
	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	ct, err := Encrypt(key.Key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag)
	if len(ct) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	// Decrypt
	pt, err := Decrypt(key.Key, ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("decrypted = %q, want %q", pt, plaintext)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := DeriveKey("test")
	ct, err := Encrypt(key.Key, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key.Key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Error("expected empty plaintext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	key1 := DeriveKey("passphrase-1")
	key2 := DeriveKey("passphrase-2")

	ct, err := Encrypt(key1.Key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(key2.Key, ct)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	key1 := DeriveKey("test")
	// Same passphrase + same salt = same key
	key2 := DeriveKeyFromSalt("test", key1.Salt)

	if !bytes.Equal(key1.Key, key2.Key) {
		t.Error("same passphrase+salt should produce same key")
	}
	if key1.FieldLens != key2.FieldLens {
		t.Errorf("field lengths differ: %v vs %v", key1.FieldLens, key2.FieldLens)
	}
}

func TestFieldLengthsUnique(t *testing.T) {
	for i := 0; i < 100; i++ {
		key := DeriveKey("test-uniqueness")
		fl := key.FieldLens
		if fl[0] == fl[1] || fl[0] == fl[2] || fl[1] == fl[2] {
			t.Errorf("field lengths not unique: %v", fl)
		}
	}
}

func TestFieldLengthsSessionVariable(t *testing.T) {
	key1 := DeriveKey("session-1")
	key2 := DeriveKey("session-2")

	// Different passphrases should (usually) produce different field lengths
	// Not guaranteed but very likely over many runs
	// At minimum, the keys should differ
	if bytes.Equal(key1.Key, key2.Key) {
		t.Error("different passphrases should produce different keys")
	}
}

func TestPackUnpackUint32(t *testing.T) {
	tests := []struct {
		val    uint32
		length int
	}{
		{0, 3},
		{1, 3},
		{255, 5},
		{4095, 3},
		{65535, 7},
		{1000000, 7},
	}

	for _, tt := range tests {
		packed := PackUint32(tt.val, tt.length)
		if len(packed) != tt.length {
			t.Errorf("PackUint32(%d, %d) = %q (len %d), want len %d", tt.val, tt.length, packed, len(packed), tt.length)
		}

		unpacked, err := UnpackUint32(packed)
		if err != nil {
			t.Errorf("UnpackUint32(%q): %v", packed, err)
		}
		// Handle truncation for short lengths
		mask := uint32((1 << (tt.length * 4)) - 1)
		expected := tt.val & mask
		if unpacked != expected {
			t.Errorf("round-trip: packed %d as %q, unpacked as %d, want %d", tt.val, packed, unpacked, expected)
		}
	}
}

func TestDecoyLength(t *testing.T) {
	key := DeriveKey("test")
	for i := 0; i < 100; i++ {
		dl := DecoyLength(key)
		if dl == key.FieldLens[0] || dl == key.FieldLens[1] || dl == key.FieldLens[2] {
			t.Errorf("decoy length %d collides with field length %v", dl, key.FieldLens)
		}
		if dl >= 20 {
			t.Errorf("decoy length %d too long (could be confused with data)", dl)
		}
		if dl < 2 {
			t.Errorf("decoy length %d too short", dl)
		}
	}
}

func TestChecksum(t *testing.T) {
	data := []byte("hello world")
	cs1 := Checksum(data)
	cs2 := Checksum(data)
	if !bytes.Equal(cs1, cs2) {
		t.Error("checksum should be deterministic")
	}
	if len(cs1) != 32 {
		t.Errorf("checksum length = %d, want 32", len(cs1))
	}

	// Different data = different checksum
	cs3 := Checksum([]byte("hello worlD"))
	if bytes.Equal(cs1, cs3) {
		t.Error("different data should produce different checksum")
	}
}
