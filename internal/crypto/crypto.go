package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// SessionKey holds the derived key and session-specific parameters.
type SessionKey struct {
	Key        []byte // 32 bytes (AES-256)
	Salt       []byte // 16 bytes (random, stored with output)
	FieldLens  [3]int // Derived field lengths for fileID, seq, total
}

// DeriveKey creates a SessionKey from a passphrase using Argon2id.
// The salt is random and must be transmitted/stored alongside the ciphertext.
func DeriveKey(passphrase string) SessionKey {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	return deriveFromSalt(passphrase, salt)
}

// DeriveKeyFromSalt recreates the same SessionKey given the passphrase and salt.
// Used by the receiver.
func DeriveKeyFromSalt(passphrase string, salt []byte) SessionKey {
	return deriveFromSalt(passphrase, salt)
}

func deriveFromSalt(passphrase string, salt []byte) SessionKey {
	// Argon2id: 64MB memory, 3 iterations, 4 threads, 32 byte output
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

	// Derive session-variable field lengths from key
	// Hash the key to get deterministic but unpredictable lengths
	h := sha256.Sum256(key)
	fieldLens := [3]int{
		3 + int(h[0]%3),  // fileID: 3-5 chars
		6 + int(h[1]%3),  // seq:    6-8 chars
		9 + int(h[2]%3),  // total:  9-11 chars
	}
	// Ensure all lengths are unique
	for fieldLens[1] == fieldLens[0] {
		fieldLens[1]++
	}
	for fieldLens[2] == fieldLens[0] || fieldLens[2] == fieldLens[1] {
		fieldLens[2]++
	}

	return SessionKey{
		Key:       key,
		Salt:      salt,
		FieldLens: fieldLens,
	}
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns: nonce (12 bytes) + ciphertext + tag (16 bytes).
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext+tag to nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext.
// Input: nonce (12 bytes) + ciphertext + tag (16 bytes).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ct, nil)
}

// DecoyLength returns a random label length that doesn't collide with
// any of the session's field lengths or common known lengths.
func DecoyLength(sk SessionKey) int {
	avoid := map[int]bool{
		sk.FieldLens[0]: true,
		sk.FieldLens[1]: true,
		sk.FieldLens[2]: true,
		33:              true, // corrID length
	}

	b := make([]byte, 1)
	for {
		rand.Read(b)
		// Decoy length: 2-15, not matching any real field
		l := 2 + int(b[0])%14
		if !avoid[l] && l < 20 { // Must be shorter than data field
			return l
		}
	}
}

// Checksum returns SHA-256 of data as bytes.
func Checksum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// PackUint32 encodes a uint32 into a hex string of exactly `length` chars.
func PackUint32(val uint32, length int) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	hex := encodeHexLower(buf)
	// Pad or trim to exact length
	for len(hex) < length {
		hex = "0" + hex
	}
	if len(hex) > length {
		hex = hex[len(hex)-length:]
	}
	return hex
}

// UnpackUint32 decodes a hex string back to uint32.
func UnpackUint32(s string) (uint32, error) {
	b, err := decodeHex(s)
	if err != nil {
		return 0, err
	}
	// Pad to 4 bytes
	for len(b) < 4 {
		b = append([]byte{0}, b...)
	}
	return binary.BigEndian.Uint32(b[len(b)-4:]), nil
}

func encodeHexLower(data []byte) string {
	const hexChars = "0123456789abcdef"
	buf := make([]byte, len(data)*2)
	for i, b := range data {
		buf[i*2] = hexChars[b>>4]
		buf[i*2+1] = hexChars[b&0x0f]
	}
	return string(buf)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := unhex(s[i])
		lo := unhex(s[i+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("invalid hex")
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out, nil
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
