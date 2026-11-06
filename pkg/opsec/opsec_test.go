package opsec

import (
	"bytes"
	"testing"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
)

func TestPadLen(t *testing.T) {

	if PadLen(0) != 0 {
		t.Fatalf("PadLen(0) should be 0")
	}
	if PadLen(4096) != 0 {
		t.Fatalf("PadLen(4096) should be 0")
	}
	if PadLen(1) != 4095 {
		t.Fatalf("PadLen(1) expected 4095, got %d", PadLen(1))
	}
	if PadLen(16384) != 0 {
		t.Fatalf("PadLen(16384) should be 0")
	}
	if PadLen(16385) <= 0 {
		t.Fatalf("PadLen(16385) should be > 0")
	}
}

func TestEncodeDecodeCfg(t *testing.T) {
	cfg := map[string][]byte{
		"short": []byte("hello short"),
		"empty": []byte{},
		"long":  bytes.Repeat([]byte{0x77}, 1000),
	}

	enc := EncodeCfg(cfg)
	dec, err := DecodeCfg(enc)
	if err != nil {
		t.Fatalf("DecodeCfg failed: %v", err)
	}

	for k, v := range cfg {
		if !bytes.Equal(v, dec[k]) {
			t.Fatalf("Mismatch for key %s", k)
		}
	}
}

func TestShareToken(t *testing.T) {
	fName := "MySecretDrive"
	fKey := bencrypt.Random(44)
	password := "SecurePass123!@"

	token, err := ExportShareToken(fName, fKey, password)
	if err != nil {
		t.Fatalf("ExportShareToken failed: %v", err)
	}

	nameOut, keyOut, err := ImportShareToken(token, password)
	if err != nil {
		t.Fatalf("ImportShareToken failed: %v", err)
	}

	if nameOut != fName {
		t.Fatalf("Name mismatch: expected %s, got %s", fName, nameOut)
	}
	if !bytes.Equal(fKey, keyOut) {
		t.Fatalf("Key mismatch")
	}

	_, _, err = ImportShareToken(token, "WrongPassword")
	if err == nil {
		t.Fatalf("Expected error with wrong password")
	}
}
