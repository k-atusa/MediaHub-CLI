package bencrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestGCM1(t *testing.T) {
	key := Random(32)
	sm, err := NewSymMaster("gcm1", key)
	if err != nil {
		t.Fatalf("NewSymMaster failed: %v", err)
	}

	testData := []byte("Hello MediaHub CLI AES-GCM 1 Encryption!")
	enc, err := sm.EnBin(testData)
	if err != nil {
		t.Fatalf("EnBin failed: %v", err)
	}

	if len(enc) != len(testData)+28 {
		t.Fatalf("Expected size %d, got %d", len(testData)+28, len(enc))
	}

	dec, err := sm.DeBin(enc)
	if err != nil {
		t.Fatalf("DeBin failed: %v", err)
	}

	if !bytes.Equal(testData, dec) {
		t.Fatalf("Decrypted data mismatch")
	}
}

func TestGCMx(t *testing.T) {
	key := Random(32)
	sm, err := NewSymMaster("gcmx1", key)
	if err != nil {
		t.Fatalf("NewSymMaster failed: %v", err)
	}

	sizes := []int64{0, 50, 1024, ChunkSize, ChunkSize + 500, ChunkSize * 2, ChunkSize*2 + 12345}
	for _, sz := range sizes {
		data := make([]byte, sz)
		io.ReadFull(rand.Reader, data)

		afterSz := AfterSize(sz)
		var encBuf bytes.Buffer
		err = sm.EnGCMx(bytes.NewReader(data), sz, &encBuf, nil)
		if err != nil {
			t.Fatalf("EnGCMx failed for size %d: %v", sz, err)
		}

		if int64(encBuf.Len()) != afterSz {
			t.Fatalf("Size %d: expected encrypted size %d, got %d", sz, afterSz, encBuf.Len())
		}

		var decBuf bytes.Buffer
		err = sm.DeGCMx(bytes.NewReader(encBuf.Bytes()), int64(encBuf.Len()), &decBuf, nil)
		if err != nil {
			t.Fatalf("DeGCMx failed for size %d: %v", sz, err)
		}

		if !bytes.Equal(data, decBuf.Bytes()) {
			t.Fatalf("Data mismatch for size %d", sz)
		}
	}
}

func TestKDF(t *testing.T) {
	hm, err := NewHashMaster("arg2st", 32, 32)
	if err != nil {
		t.Fatalf("NewHashMaster failed: %v", err)
	}

	pw := []byte("my_secret_password")
	salt := Random(32)

	pwStore, keyGen, err := hm.KDF(pw, salt)
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}

	if len(pwStore) != 32 || len(keyGen) != 32 {
		t.Fatalf("Invalid KDF output lengths: %d, %d", len(pwStore), len(keyGen))
	}
}
