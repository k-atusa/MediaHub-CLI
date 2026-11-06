package bencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

const ChunkSize = 1048576

func AfterSize(size int64) int64 {
	c := size/ChunkSize + 1
	if size != 0 && size%ChunkSize == 0 {
		c -= 1
	}
	return size + 12 + 16*c
}

func (sm *SymMaster) EnGCMx(src io.Reader, size int64, dst io.Writer, progCb func(processed int64)) error {
	block, err := aes.NewCipher(sm.Key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	globalIV := Random(12)
	if _, err := dst.Write(globalIV); err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	var count uint64 = 0
	var rem = size
	var processed int64 = 0

	for rem > 0 {
		toRead := int64(ChunkSize)
		if rem < toRead {
			toRead = rem
		}
		n, err := io.ReadFull(src, buf[:toRead])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n == 0 {
			break
		}

		iv := MkIV(globalIV, count)
		count++

		ciphertext := aesGCM.Seal(nil, iv, buf[:n], nil)
		if _, err := dst.Write(ciphertext); err != nil {
			return err
		}

		rem -= int64(n)
		processed += int64(n)
		if progCb != nil {
			progCb(processed)
		}
	}

	if size == 0 {
		iv := MkIV(globalIV, 0)
		ciphertext := aesGCM.Seal(nil, iv, []byte{}, nil)
		if _, err := dst.Write(ciphertext); err != nil {
			return err
		}
		if progCb != nil {
			progCb(0)
		}
	}

	return nil
}

func (sm *SymMaster) DeGCMx(src io.Reader, encSize int64, dst io.Writer, progCb func(processed int64)) error {
	if encSize < 28 {
		return errors.New("cipher too short to decrypt")
	}

	globalIV := make([]byte, 12)
	if _, err := io.ReadFull(src, globalIV); err != nil {
		return err
	}

	block, err := aes.NewCipher(sm.Key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	remEnc := encSize - 12
	encChunkBuf := make([]byte, ChunkSize+16)
	var count uint64 = 0
	var processed int64 = 12

	for remEnc > 0 {
		toRead := int64(ChunkSize + 16)
		if remEnc < toRead {
			toRead = remEnc
		}
		n, err := io.ReadFull(src, encChunkBuf[:toRead])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n == 0 {
			break
		}

		iv := MkIV(globalIV, count)
		count++

		plaintext, err := aesGCM.Open(nil, iv, encChunkBuf[:n], nil)
		if err != nil {
			return err
		}

		if _, err := dst.Write(plaintext); err != nil {
			return err
		}

		remEnc -= int64(n)
		processed += int64(n)
		if progCb != nil {
			progCb(processed)
		}
	}

	return nil
}

func (sm *SymMaster) DecryptChunk(globalIV []byte, chunkIdx uint64, cipherChunk []byte) ([]byte, error) {
	if len(cipherChunk) < 16 {
		return nil, errors.New("chunk too short")
	}
	block, err := aes.NewCipher(sm.Key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := MkIV(globalIV, chunkIdx)
	return aesGCM.Open(nil, iv, cipherChunk, nil)
}
