package utils

import (
	"encoding/pem"
	"errors"
	"net"
	"testing"
)

func TestB2SAndS2BRoundTrip(t *testing.T) {
	if got := B2S([]byte("hello")); got != "hello" {
		t.Fatalf("B2S: got %q, want %q", got, "hello")
	}
	if got := B2S(nil); got != "" {
		t.Fatalf("B2S(nil): got %q, want empty", got)
	}
	if got := S2B("world"); string(got) != "world" {
		t.Fatalf("S2B: got %q, want %q", got, "world")
	}
	if got := S2B(""); got != nil {
		t.Fatalf("S2B(\"\"): got %v, want nil", got)
	}
}

func TestDecodePEMOrBase64(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}

	// Base64 input.
	if got, err := DecodePEMOrBase64([]byte("AQID"), "CERTIFICATE"); err != nil {
		t.Fatalf("base64 decode error: %v", err)
	} else if string(got) != string(raw) {
		t.Fatalf("base64 decode: got %v, want %v", got, raw)
	}

	// PEM input with the expected header.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	if got, err := DecodePEMOrBase64(pemBytes, "CERTIFICATE"); err != nil {
		t.Fatalf("PEM decode error: %v", err)
	} else if string(got) != string(raw) {
		t.Fatalf("PEM decode: got %v, want %v", got, raw)
	}

	// Invalid base64 input.
	if _, err := DecodePEMOrBase64([]byte("not valid base64!!!"), "CERTIFICATE"); err == nil {
		t.Fatal("expected error for invalid base64 input")
	}
}

func TestIsTimeoutError(t *testing.T) {
	if !IsTimeoutError(&net.DNSError{IsTimeout: true}) {
		t.Fatal("expected true for a timeout net.Error")
	}
	if IsTimeoutError(&net.DNSError{IsTimeout: false}) {
		t.Fatal("expected false for a non-timeout net.Error")
	}
	if IsTimeoutError(errors.New("plain error")) {
		t.Fatal("expected false for a non-net error")
	}
}

func TestVersionString(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{NOT_INSTALLED, "[" + NOT_INSTALLED + "]"},
		{"v0.0.0-0-gabcdef1", "v0.0.0-0-gabcdef1"},
		{"v0.0.0-20210101000000-abcdef123456", "v0.0.0-20210101000000-abcdef123456"},
		{"v1.2.3", "v1.2.3"},
		{"1.2.3", "v1.2.3"},
		{"abcdef1234567890", "gabcdef1"},
		{"abc", "(abc)"},
	}
	for _, c := range cases {
		if got := VersionString(c.in); got != c.want {
			t.Errorf("VersionString(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGetPackagePath(t *testing.T) {
	// In a test binary, build info is available, so the path is non-empty.
	if GetPackagePath() == "" {
		t.Fatal("expected a non-empty package path")
	}
}
