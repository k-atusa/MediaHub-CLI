package bencode

import (
	"bytes"
	"testing"
)

func TestBencode(t *testing.T) {
	data := []byte("Hello MediaHub CLI! 1234567890!@#$%^&*()_+~`|}{[]:;?><,./")
	enc, err := Encode64(data, "#", 10, 2)
	if err != nil {
		t.Fatalf("Encode64 failed: %v", err)
	}

	dec, err := Decode64(enc, "#")
	if err != nil {
		t.Fatalf("Decode64 failed: %v", err)
	}

	if !bytes.Equal(data, dec) {
		t.Fatalf("Expected %s, got %s", data, dec)
	}

	encRaw, err := Encode64(data, "", 40, 10)
	if err != nil {
		t.Fatalf("Encode64 raw failed: %v", err)
	}
	decRaw, err := Decode64(encRaw, "")
	if err != nil {
		t.Fatalf("Decode64 raw failed: %v", err)
	}
	if !bytes.Equal(data, decRaw) {
		t.Fatalf("Raw decode mismatch")
	}

	pw1 := NormPW("한글암호123")
	if len(pw1) == 0 {
		t.Fatalf("NormPW returned empty")
	}
}
