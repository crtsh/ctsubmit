package loglists

import (
	"crypto/sha256"
	"testing"
)

func TestRegisterAndGetLogName(t *testing.T) {
	var keyID [sha256.Size]byte
	copy(keyID[:], []byte("test-log-id-for-register-getname"))

	RegisterLogName(keyID, "Test Operator", "Test Log")

	operator, name := GetLogName(keyID[:])
	if operator != "Test Operator" || name != "Test Log" {
		t.Fatalf("GetLogName: got (%q, %q), want (%q, %q)", operator, name, "Test Operator", "Test Log")
	}
}

func TestGetLogNameUnknown(t *testing.T) {
	unknown := make([]byte, sha256.Size)
	unknown[0] = 0xff

	operator, name := GetLogName(unknown)
	if operator != "" || name != "" {
		t.Fatalf("GetLogName(unknown): got (%q, %q), want empty strings", operator, name)
	}
}

func TestGetLogNameWrongLength(t *testing.T) {
	// A LogID that isn't sha256-sized can't match the extra-names map.
	operator, name := GetLogName([]byte{0x01, 0x02})
	if operator != "" || name != "" {
		t.Fatalf("GetLogName(short): got (%q, %q), want empty strings", operator, name)
	}
}
