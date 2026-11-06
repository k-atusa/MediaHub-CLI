package opsec

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/k-atusa/mediahub-cli/pkg/bencode"
	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
)

// Opsec implements the MediaHub / USAG Opsec header specification.
type Opsec struct {
	SaltLen     int
	HeadAlgo    string
	Msg         string
	MsgInfo     []byte
	Salt        []byte
	EncHeadData []byte

	Smsg     string
	SmsgInfo []byte
	Sign     []byte

	BodyAlgo string
	BodyKey  []byte
	BodySize int64
	BodyInfo []byte
}

func NewOpsec() *Opsec {
	op := &Opsec{
		SaltLen:  32,
		BodySize: -1,
	}
	return op
}

func (op *Opsec) Clear() {
	op.Salt = nil
	op.EncHeadData = nil
	op.Msg = ""
	op.MsgInfo = nil
	op.Smsg = ""
	op.SmsgInfo = nil
	op.Sign = nil
	op.BodyKey = nil
	op.BodyInfo = nil
	op.BodyAlgo = ""
	op.BodySize = -1
	op.HeadAlgo = ""
}

func (op *Opsec) wrapEncHead() []byte {
	cfg := make(map[string][]byte)
	if op.Smsg != "" {
		cfg["smsg"] = []byte(op.Smsg)
	}
	if len(op.SmsgInfo) > 0 {
		cfg["sinf"] = op.SmsgInfo
	}
	if len(op.Sign) > 0 {
		cfg["sgn"] = op.Sign
	}
	if op.BodyAlgo != "" {
		cfg["bal"] = []byte(op.BodyAlgo)
	}
	if len(op.BodyKey) > 0 {
		cfg["bkey"] = op.BodyKey
	}
	if op.BodySize >= 0 {
		if op.BodySize < 65536 {
			cfg["bsz"] = EncodeInt(uint64(op.BodySize), 2)
		} else if op.BodySize < 4294967296 {
			cfg["bsz"] = EncodeInt(uint64(op.BodySize), 4)
		} else {
			cfg["bsz"] = EncodeInt(uint64(op.BodySize), 8)
		}
	}
	if len(op.BodyInfo) > 0 {
		cfg["binf"] = op.BodyInfo
	}
	return EncodeCfg(cfg)
}

func (op *Opsec) unwrapEncHead(data []byte) error {
	cfg, err := DecodeCfg(data)
	if err != nil {
		return err
	}
	if val, ok := cfg["smsg"]; ok {
		op.Smsg = string(val)
	}
	if val, ok := cfg["sinf"]; ok {
		op.SmsgInfo = val
	}
	if val, ok := cfg["sgn"]; ok {
		op.Sign = val
	}
	if val, ok := cfg["bal"]; ok {
		op.BodyAlgo = string(val)
	}
	if val, ok := cfg["bkey"]; ok {
		op.BodyKey = val
	}
	if val, ok := cfg["bsz"]; ok {
		op.BodySize = int64(DecodeInt(val))
	}
	if val, ok := cfg["binf"]; ok {
		op.BodyInfo = val
	}
	return nil
}

// Encpw encrypts the Opsec header using a password-derived key.
func (op *Opsec) Encpw(method string, pw []byte, kf []byte) ([]byte, error) {
	op.HeadAlgo = method
	op.Salt = bencrypt.Random(op.SaltLen)
	if op.BodySize >= 0 {
		op.BodyKey = bencrypt.Random(32)
	}

	hm, err := bencrypt.NewHashMaster(method, 32, 32)
	if err != nil {
		return nil, err
	}
	combined := append(append([]byte{}, pw...), kf...)
	_, hkey, err := hm.KDF(combined, op.Salt)
	if err != nil {
		return nil, err
	}

	headData := op.wrapEncHead()
	sm, err := bencrypt.NewSymMaster("gcm1", hkey)
	if err != nil {
		return nil, err
	}

	op.EncHeadData, err = sm.EnBin(headData)
	if err != nil {
		return nil, err
	}

	cfg := make(map[string][]byte)
	if op.Msg != "" {
		cfg["msg"] = []byte(op.Msg)
	}
	if len(op.MsgInfo) > 0 {
		cfg["minf"] = op.MsgInfo
	}
	cfg["hal"] = []byte(op.HeadAlgo)
	cfg["salt"] = op.Salt
	cfg["ehd"] = op.EncHeadData

	return EncodeCfg(cfg), nil
}

// View loads the outer Opsec header fields without decrypting the payload.
func (op *Opsec) View(data []byte) error {
	op.Clear()
	cfg, err := DecodeCfg(data)
	if err != nil {
		return err
	}
	if val, ok := cfg["msg"]; ok {
		op.Msg = string(val)
	}
	if val, ok := cfg["minf"]; ok {
		op.MsgInfo = val
	}
	if val, ok := cfg["hal"]; ok {
		op.HeadAlgo = string(val)
	}
	if val, ok := cfg["salt"]; ok {
		op.Salt = val
	}
	if val, ok := cfg["ehd"]; ok {
		op.EncHeadData = val
	}
	return nil
}

// Decpw decrypts the inner Opsec payload using a password.
func (op *Opsec) Decpw(pw []byte, kf []byte) error {
	if op.HeadAlgo == "" || len(op.EncHeadData) == 0 {
		return errors.New("opsec header not initialized or invalid")
	}
	hm, err := bencrypt.NewHashMaster(op.HeadAlgo, 32, 32)
	if err != nil {
		return err
	}
	combined := append(append([]byte{}, pw...), kf...)
	_, hkey, err := hm.KDF(combined, op.Salt)
	if err != nil {
		return err
	}

	sm, err := bencrypt.NewSymMaster("gcm1", hkey)
	if err != nil {
		return err
	}

	headData, err := sm.DeBin(op.EncHeadData)
	if err != nil {
		return fmt.Errorf("decryption failed (invalid password or corrupted header): %w", err)
	}

	return op.unwrapEncHead(headData)
}

// ReadHeader reads a YAS2-framed Opsec header from an io.Reader.
func ReadHeader(r io.Reader, maxCut int) ([]byte, error) {
	var totalRead int
	magic := make([]byte, 4)
	for {
		n, err := io.ReadFull(r, magic)
		totalRead += n
		if err != nil {
			return nil, err
		}
		if string(magic) == "YAS2" {
			szBuf := make([]byte, 2)
			if _, err := io.ReadFull(r, szBuf); err != nil {
				return nil, err
			}
			size := int(DecodeInt(szBuf))
			if size == 65535 {
				if _, err := io.ReadFull(r, szBuf); err != nil {
					return nil, err
				}
				size += int(DecodeInt(szBuf))
			}
			head := make([]byte, size)
			if _, err := io.ReadFull(r, head); err != nil {
				return nil, err
			}
			return head, nil
		}
		// skip 124 bytes
		skip := make([]byte, 124)
		n, _ = io.ReadFull(r, skip)
		totalRead += n
		if maxCut > 0 && totalRead > maxCut {
			return nil, errors.New("YAS2 magic not found within cut limit")
		}
	}
}

// WriteHeader writes a YAS2-framed Opsec header to an io.Writer.
func WriteHeader(w io.Writer, head []byte) error {
	if _, err := w.Write([]byte("YAS2")); err != nil {
		return err
	}
	size := len(head)
	if size < 65535 {
		if _, err := w.Write(EncodeInt(uint64(size), 2)); err != nil {
			return err
		}
	} else if size <= 65535*2 {
		if _, err := w.Write(EncodeInt(65535, 2)); err != nil {
			return err
		}
		if _, err := w.Write(EncodeInt(uint64(size-65535), 2)); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("header too big: %d", size)
	}
	_, err := w.Write(head)
	return err
}

// ExportShareToken packages a folder name and folderKey into an encrypted share token string.
func ExportShareToken(folderName string, folderKey []byte, password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	op := NewOpsec()
	op.Smsg = folderName
	op.SmsgInfo = folderKey

	head, err := op.Encpw("arg2st", bencode.NormPW(password), nil)
	if err != nil {
		return "", err
	}

	return bencode.Encode64(head, "#", 40, 10)
}

// ImportShareToken decrypts a share token string and returns the folder name and folderKey.
func ImportShareToken(tokenText string, password string) (string, []byte, error) {
	if password == "" || strings.TrimSpace(tokenText) == "" {
		return "", nil, errors.New("password and token cannot be empty")
	}
	raw, err := bencode.Decode64(strings.TrimSpace(tokenText), "#")
	if err != nil {
		return "", nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	op := NewOpsec()
	if err := op.View(raw); err != nil {
		return "", nil, fmt.Errorf("failed to view header: %w", err)
	}

	if err := op.Decpw(bencode.NormPW(password), nil); err != nil {
		return "", nil, err
	}

	if op.Smsg == "" || len(op.SmsgInfo) == 0 {
		return "", nil, errors.New("empty folder share payload")
	}

	resKey := make([]byte, len(op.SmsgInfo))
	copy(resKey, op.SmsgInfo)
	return op.Smsg, resKey, nil
}
