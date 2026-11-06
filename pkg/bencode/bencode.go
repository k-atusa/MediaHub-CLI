package bencode

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var SplitableChars = []string{"!", "@", "#", "$", "%", "^", "&", "*", "~", "|"}

func isSplitable(s string) bool {
	for _, c := range SplitableChars {
		if c == s {
			return true
		}
	}
	return false
}

// Encode64 encodes data into base64, optionally formatted with delimiters and line/column wrapping.
func Encode64(data []byte, spliter string, linenum int, colnum int) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	raw := base64.StdEncoding.EncodeToString(data)
	if spliter == "" {
		return raw, nil
	}
	if !isSplitable(spliter) {
		return "", errors.New("invalid spliter option")
	}
	if linenum <= 0 {
		linenum = 40
	}
	if colnum <= 0 {
		colnum = 10
	}

	var lines []string
	for i := 0; i < len(raw); i += linenum {
		end := i + linenum
		if end > len(raw) {
			end = len(raw)
		}
		lines = append(lines, raw[i:end])
	}

	var cols [][]string
	for i := 0; i < len(lines); i += colnum {
		end := i + colnum
		if end > len(lines) {
			end = len(lines)
		}
		cols = append(cols, lines[i:end])
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%sSTART%s\n", spliter, spliter))
	totalCols := len(cols)
	for i, col := range cols {
		sb.WriteString(fmt.Sprintf("%s%d/%d%s\n", spliter, i+1, totalCols, spliter))
		sb.WriteString(strings.Join(col, "\n"))
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("%sEND%s", spliter, spliter))
	return sb.String(), nil
}

// Decode64 removes whitespace and optional delimiter comments, then decodes standard base64.
func Decode64(data string, spliter string) ([]byte, error) {
	// Remove \t, \r, \n, and space
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\r", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.ReplaceAll(data, " ", "")

	if spliter != "" {
		if !isSplitable(spliter) {
			return nil, errors.New("invalid spliter option")
		}
		var clean strings.Builder
		appendable := true
		for i := 0; i < len(data); i++ {
			if string(data[i]) == spliter {
				appendable = !appendable
			} else if appendable {
				clean.WriteByte(data[i])
			}
		}
		data = clean.String()
	}

	if data == "" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(data)
}

// NormPW normalizes a password string using Unicode NFC and returns UTF-8 bytes.
func NormPW(pw string) []byte {
	if pw == "" {
		return []byte{}
	}
	return norm.NFC.Bytes([]byte(pw))
}
