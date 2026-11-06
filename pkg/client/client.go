package client

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/k-atusa/mediahub-cli/pkg/bencode"
	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
)

const Pepper = "_PROJECT_WHY_MEDIAHUB_PEPPER_2026_!@#$"

type FileInfo struct {
	Name string
	Size int64
	PID  string
	Key  []byte
}

type Client struct {
	ServerURL   string
	Username    string
	Password    string
	InsecureTLS bool
	UHash       string
	UKey        []byte
	FldMap      map[string][]byte
	HTTPClient  *http.Client
}

func NewClient(serverURL, username, password string, insecureTLS bool) *Client {
	cleanURL := strings.TrimRight(serverURL, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS,
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   0,
	}

	return &Client{
		ServerURL:   cleanURL,
		Username:    username,
		Password:    password,
		InsecureTLS: insecureTLS,
		FldMap:      make(map[string][]byte),
		HTTPClient:  httpClient,
	}
}

func (c *Client) UsrPid(key []byte) string {
	return hex.EncodeToString(bencrypt.SHA3256(key)[:16])
}

func (c *Client) ObjPid(key []byte) string {
	if len(key) < 44 {
		return ""
	}
	return hex.EncodeToString(key[32:44])
}

func (c *Client) Auth() error {
	salt := bencrypt.SHA3256([]byte(c.Username + Pepper))
	pw := bencode.NormPW(c.Password)

	hm, err := bencrypt.NewHashMaster("arg2st", 32, 32)
	if err != nil {
		return err
	}

	stKey, uKey, err := hm.KDF(pw, salt)
	if err != nil {
		return err
	}

	c.UHash = c.UsrPid(stKey)
	c.UKey = uKey[:32]
	return nil
}

func (c *Client) SetAuth(uHash string, uKey []byte) {
	c.UHash = uHash
	c.UKey = make([]byte, len(uKey))
	copy(c.UKey, uKey)
}

type ProgressReader struct {
	reader     io.Reader
	totalBytes int64
	readBytes  int64
	startTime  time.Time
	lastReport time.Time
	lastBytes  int64
	onProgress func(sent, total int64, speed float64)
}

func NewProgressReader(r io.Reader, total int64, cb func(sent, total int64, speed float64)) *ProgressReader {
	now := time.Now()
	return &ProgressReader{
		reader:     r,
		totalBytes: total,
		startTime:  now,
		lastReport: now,
		onProgress: cb,
	}
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.readBytes += int64(n)
		now := time.Now()
		elapsed := now.Sub(pr.lastReport).Seconds()
		if elapsed >= 0.25 && pr.onProgress != nil {
			speed := float64(pr.readBytes-pr.lastBytes) / elapsed
			pr.onProgress(pr.readBytes, pr.totalBytes, speed)
			pr.lastReport = now
			pr.lastBytes = pr.readBytes
		}
	}
	return n, err
}
