package bencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Random generates cryptographically secure pseudo-random bytes.
func Random(size int) []byte {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return b
}

// SHA3256 computes the SHA3-256 digest of data.
func SHA3256(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// HMAC3256 computes HMAC using SHA3-256.
func HMAC3256(key []byte, data []byte) []byte {
	mac := hmac.New(sha3.New256, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// SHA3512 computes the SHA3-512 digest of data.
func SHA3512(data []byte) []byte {
	h := sha3.New512()
	h.Write(data)
	return h.Sum(nil)
}

// HMAC3512 computes HMAC using SHA3-512.
func HMAC3512(key []byte, data []byte) []byte {
	mac := hmac.New(sha3.New512, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// GenKey derives a key from master data using HMAC-SHA3-512.
func GenKey(data []byte, lbl string, size int) ([]byte, error) {
	key := HMAC3512(data, []byte(lbl))
	if size > len(key) {
		return nil, errors.New("key size too large")
	}
	res := make([]byte, size)
	copy(res, key[:size])
	return res, nil
}

// MkIV creates a chunk IV by XORing globalIV[4:12] with counter (8 bytes little-endian).
func MkIV(globalIV []byte, count uint64) []byte {
	iv := make([]byte, len(globalIV))
	copy(iv, globalIV)
	var cBytes [8]byte
	binary.LittleEndian.PutUint64(cBytes[:], count)
	for i := 0; i < 8 && 4+i < len(iv); i++ {
		iv[4+i] ^= cBytes[i]
	}
	return iv
}

// Argon2low executes Argon2id with low memory parameters (64MB, t=4, p=8).
func Argon2low(pw []byte, salt []byte) []byte {
	return argon2.IDKey(pw, salt, 4, 65536, 8, 64)
}

// Argon2st executes Argon2id with standard memory parameters (256MB, t=3, p=6).
func Argon2st(pw []byte, salt []byte) []byte {
	return argon2.IDKey(pw, salt, 3, 262144, 6, 64)
}

// HashMaster manages password hashing and user key derivation.
type HashMaster struct {
	Algo     string
	HashSize int
	KeySize  int
}

func NewHashMaster(algo string, hashSize int, keySize int) (*HashMaster, error) {
	if algo != "sha3" && algo != "arg2low" && algo != "arg2st" {
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
	if hashSize <= 0 {
		hashSize = 32
	}
	if keySize <= 0 {
		keySize = 32
	}
	return &HashMaster{
		Algo:     algo,
		HashSize: hashSize,
		KeySize:  keySize,
	}, nil
}

// KDF derives pwStore and keyGen from password and salt.
func (hm *HashMaster) KDF(pw []byte, salt []byte) (pwStore []byte, keyGen []byte, err error) {
	var lblStore, lblKeygen string
	var master []byte

	switch hm.Algo {
	case "sha3":
		lblStore, lblKeygen = "PWHASH_SHA3", "KEYGEN_SHA3"
		combined := append(append([]byte{}, salt...), pw...)
		master = SHA3512(combined)
	case "arg2low":
		lblStore, lblKeygen = "PWHASH_ARG2LOW", "KEYGEN_ARG2LOW"
		master = Argon2low(pw, salt)
	case "arg2st":
		lblStore, lblKeygen = "PWHASH_ARG2ST", "KEYGEN_ARG2ST"
		master = Argon2st(pw, salt)
	default:
		return nil, nil, fmt.Errorf("unknown algorithm: %s", hm.Algo)
	}

	pwStore, err = GenKey(master, lblStore, hm.HashSize)
	if err != nil {
		return nil, nil, err
	}
	keyGen, err = GenKey(master, lblKeygen, hm.KeySize)
	if err != nil {
		return nil, nil, err
	}
	return pwStore, keyGen, nil
}

// SymMaster manages AES-256-GCM encryption for binary data and streams.
type SymMaster struct {
	Algo string
	Key  []byte
}

func NewSymMaster(algo string, key []byte) (*SymMaster, error) {
	if algo != "gcm1" && algo != "gcmx1" {
		return nil, fmt.Errorf("unsupported symmetric algorithm: %s", algo)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("SYM keysize must be 32: got %d", len(key))
	}
	k := make([]byte, 32)
	copy(k, key)
	return &SymMaster{
		Algo: algo,
		Key:  k,
	}, nil
}

// EnBin encrypts binary data using AES-GCM (12-byte IV + ciphertext + 16-byte Tag).
func (sm *SymMaster) EnBin(data []byte) ([]byte, error) {
	if sm.Algo != "gcm1" {
		return nil, errors.New("EnBin only supports gcm1 directly, use EnGCMx for gcmx1")
	}
	block, err := aes.NewCipher(sm.Key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := Random(12)
	ciphertext := aesGCM.Seal(nil, iv, data, nil)
	result := make([]byte, 12+len(ciphertext))
	copy(result[:12], iv)
	copy(result[12:], ciphertext)
	return result, nil
}

// DeBin decrypts binary data encrypted with EnBin.
func (sm *SymMaster) DeBin(data []byte) ([]byte, error) {
	if sm.Algo != "gcm1" {
		return nil, errors.New("DeBin only supports gcm1 directly")
	}
	if len(data) < 28 {
		return nil, errors.New("cipher too short")
	}
	iv := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(sm.Key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM.Open(nil, iv, ciphertext, nil)
}
