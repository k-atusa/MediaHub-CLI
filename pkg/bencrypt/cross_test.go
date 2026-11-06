package bencrypt

import (
	"bytes"
	"encoding/hex"
	"os/exec"
	"testing"
)

func TestPythonCrossCompatibility(t *testing.T) {
	// Let's run a quick python script using python3 that imports ../MediaHub-Desktop
	// and verifies that Go and Python produce matching outputs.
	cmd := exec.Command("python3", "-c", `
import sys
sys.path.append("../MediaHub-Desktop")
import Bencrypt, Bencode
import os

pw = Bencode.NormPW("test_password_123")
salt = b"\x01" * 32
hm = Bencrypt.HashMaster("arg2st")
pwStore, keyGen = hm.KDF(pw, salt)

# AES-GCM 1
key = b"\x42" * 32
sm = Bencrypt.SymMaster("gcm1", key)
plain = b"Cross-language verification test string!"
ciph = sm.EnBin(plain)

print(f"{pwStore.hex()}:{keyGen.hex()}:{ciph.hex()}")
`)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("Python3 or dependencies not available for cross-test: %v", err)
		return
	}

	parts := bytes.Split(bytes.TrimSpace(out), []byte(":"))
	if len(parts) != 3 {
		t.Fatalf("Unexpected python output format: %s", out)
	}

	pyPwStore, _ := hex.DecodeString(string(parts[0]))
	pyKeyGen, _ := hex.DecodeString(string(parts[1]))
	pyCiph, _ := hex.DecodeString(string(parts[2]))

	// 1. Verify KDF matches
	hm, err := NewHashMaster("arg2st", 32, 32)
	if err != nil {
		t.Fatalf("NewHashMaster: %v", err)
	}
	pw := []byte("test_password_123")
	salt := bytes.Repeat([]byte{1}, 32)
	goPwStore, goKeyGen, err := hm.KDF(pw, salt)
	if err != nil {
		t.Fatalf("Go KDF: %v", err)
	}

	if !bytes.Equal(pyPwStore, goPwStore) {
		t.Fatalf("pwStore mismatch! py: %x, go: %x", pyPwStore, goPwStore)
	}
	if !bytes.Equal(pyKeyGen, goKeyGen) {
		t.Fatalf("keyGen mismatch! py: %x, go: %x", pyKeyGen, goKeyGen)
	}

	// 2. Decrypt Python's GCM ciphertext in Go
	key := bytes.Repeat([]byte{0x42}, 32)
	sm, err := NewSymMaster("gcm1", key)
	if err != nil {
		t.Fatalf("NewSymMaster: %v", err)
	}
	dec, err := sm.DeBin(pyCiph)
	if err != nil {
		t.Fatalf("Failed to decrypt python cipher: %v", err)
	}
	if string(dec) != "Cross-language verification test string!" {
		t.Fatalf("Decrypted text mismatch: %s", dec)
	}
}
