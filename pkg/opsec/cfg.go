package opsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sort"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
)

// PadLen calculates the obfuscated padding length based on the original encrypted file size.
func PadLen(size int64) int64 {
	if size <= 0 {
		return 0
	}

	// 1. 0 - 16k: 4k * N
	if size <= 16384 {
		remainder := size % 4096
		if remainder == 0 {
			return 0
		}
		return 4096 - remainder
	}

	bitLen := bits.Len64(uint64(size))
	var k int
	if bitLen <= 24 { // 16k - 16m: K=2
		k = 2
	} else if bitLen <= 29 { // 16m - 512m: K=3
		k = 3
	} else if bitLen <= 33 { // 512m - 8g: K=4
		k = 4
	} else { // 8g+: K=5
		k = 5
	}

	shift := bitLen - k
	mask := (uint64(1) << shift) - 1
	if (uint64(size) & mask) == 0 {
		return 0
	}

	aftersize := ((uint64(size) >> shift) + 1) << shift
	return int64(aftersize) - size
}

// PadFile writes size bytes of random padding to dst.
func PadFile(dst io.Writer, size int64) error {
	const bufSize = 1048576 // 1MB
	rem := size
	for rem > 0 {
		toWrite := rem
		if toWrite > bufSize {
			toWrite = bufSize
		}
		randBytes := bencrypt.Random(int(toWrite))
		if _, err := dst.Write(randBytes); err != nil {
			return err
		}
		rem -= toWrite
	}
	return nil
}

// EncodeInt serializes an integer into little-endian bytes of specified length.
func EncodeInt(data uint64, size int) []byte {
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = byte(data >> (8 * i))
	}
	return buf
}

// DecodeInt deserializes little-endian bytes into uint64.
func DecodeInt(data []byte) uint64 {
	var val uint64
	for i := 0; i < len(data) && i < 8; i++ {
		val |= uint64(data[i]) << (8 * i)
	}
	return val
}

// EncodeCfg encodes key-value pairs into Opsec Cfg format:
// [keyLen 1B (keyLen > 127 if dataLen > 255)][key][dataLen 1B or 2B][data]
func EncodeCfg(data map[string][]byte) []byte {
	// Deterministic ordering by sorting keys
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var result []byte
	for _, k := range keys {
		val := data[k]
		keyBytes := []byte(k)
		keyLen := len(keyBytes)
		dataLen := len(val)

		if keyLen > 127 {
			panic(fmt.Sprintf("key length too long: %d", keyLen))
		}
		if dataLen > 65535 {
			panic(fmt.Sprintf("data size too big: %d", dataLen))
		}

		if dataLen > 255 {
			result = append(result, byte(keyLen+128))
			result = append(result, keyBytes...)
			lenBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBytes, uint16(dataLen))
			result = append(result, lenBytes...)
		} else {
			result = append(result, byte(keyLen))
			result = append(result, keyBytes...)
			result = append(result, byte(dataLen))
		}
		result = append(result, val...)
	}
	return result
}

// DecodeCfg decodes Opsec Cfg binary format into key-value pairs.
func DecodeCfg(data []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	offset := 0
	totalLen := len(data)

	for offset < totalLen {
		if offset >= totalLen {
			break
		}
		rawKeyLen := int(data[offset])
		offset++
		isLongData := false
		if rawKeyLen > 127 {
			rawKeyLen -= 128
			isLongData = true
		}

		if offset+rawKeyLen > totalLen {
			return nil, errors.New("corrupted config: unexpected EOF reading key")
		}
		key := string(data[offset : offset+rawKeyLen])
		offset += rawKeyLen

		var dataLen int
		if isLongData {
			if offset+2 > totalLen {
				return nil, errors.New("corrupted config: unexpected EOF reading 2-byte data length")
			}
			dataLen = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > totalLen {
				return nil, errors.New("corrupted config: unexpected EOF reading 1-byte data length")
			}
			dataLen = int(data[offset])
			offset++
		}

		if offset+dataLen > totalLen {
			return nil, errors.New("corrupted config: unexpected EOF reading data payload")
		}
		val := make([]byte, dataLen)
		copy(val, data[offset:offset+dataLen])
		result[key] = val
		offset += dataLen
	}

	return result, nil
}
