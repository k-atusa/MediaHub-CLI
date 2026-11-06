package proxy

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
	"github.com/k-atusa/mediahub-cli/pkg/client"
	"github.com/k-atusa/mediahub-cli/pkg/opsec"
)

const (
	PlainChunkSize  = 1048576 // 1MB
	CipherChunkSize = PlainChunkSize + 16
)

// StreamProxy provides on-demand decrypted HTTP streaming for encrypted media blobs.
type StreamProxy struct {
	server   *http.Server
	listener net.Listener
	client   *client.Client
	fPid     string
	flMap    map[string][]byte
	port     int
	mu       sync.RWMutex

	ivCache    map[string][]byte
	chunkCache map[string][]byte
	cacheMu    sync.Mutex
}

// NewStreamProxy creates a new streaming proxy server.
func NewStreamProxy(cli *client.Client, port int) *StreamProxy {
	return &StreamProxy{
		client:     cli,
		flMap:      make(map[string][]byte),
		port:       port,
		ivCache:    make(map[string][]byte),
		chunkCache: make(map[string][]byte),
	}
}

// UpdateContext updates the active folder PID and file mapping for the proxy.
func (sp *StreamProxy) UpdateContext(fPid string, flMap map[string][]byte) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	sp.fPid = fPid
	sp.flMap = make(map[string][]byte, len(flMap))
	for k, v := range flMap {
		sp.flMap[k] = v
	}

	sp.cacheMu.Lock()
	sp.ivCache = make(map[string][]byte)
	sp.chunkCache = make(map[string][]byte)
	sp.cacheMu.Unlock()
}

// Start binds and starts the HTTP proxy server.
func (sp *StreamProxy) Start() (int, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", sp.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// If preferred port is busy, fallback to random available port
		if sp.port != 0 {
			ln, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return 0, err
			}
		} else {
			return 0, err
		}
	}
	sp.listener = ln
	sp.port = ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/stream/", sp.handleStream)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	sp.server = &http.Server{
		Handler: corsMiddleware(mux),
	}

	go func() {
		_ = sp.server.Serve(ln)
	}()

	return sp.port, nil
}

// Stop gracefully shuts down the proxy server.
func (sp *StreamProxy) Stop() error {
	if sp.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return sp.server.Shutdown(ctx)
	}
	return nil
}

// StreamURL returns the full local streaming URL for a file in the folder.
func (sp *StreamProxy) StreamURL(fPid string, fileName string) string {
	escapedName := url.PathEscape(fileName)
	return fmt.Sprintf("http://127.0.0.1:%d/stream/%s/%s", sp.port, fPid, escapedName)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Range")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var rangeRegex = regexp.MustCompile(`^bytes=(\d+)-(\d*)$`)
var rangeSuffixRegex = regexp.MustCompile(`^bytes=-(\d+)$`)

func (sp *StreamProxy) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL format: /stream/{folderPid}/{fileName}
	path := strings.TrimPrefix(r.URL.Path, "/stream/")
	slashIdx := strings.Index(path, "/")
	if slashIdx == -1 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	reqFPid := path[:slashIdx]
	rawFileName := path[slashIdx+1:]
	fileName, err := url.PathUnescape(rawFileName)
	if err != nil {
		fileName = rawFileName
	}

	sp.mu.RLock()
	flInfo, exists := sp.flMap[fileName]
	currentFPid := sp.fPid
	cli := sp.client
	sp.mu.RUnlock()

	if !exists || currentFPid != reqFPid || len(flInfo) < 52 {
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}

	fk := flInfo[:44]
	aesKey := fk[:32]
	origSz := int64(opsec.DecodeInt(flInfo[44:52]))
	fpid := cli.ObjPid(fk)

	// Parse Range request
	var rS int64 = 0
	var rE int64 = origSz - 1
	partial := false

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		if m := rangeRegex.FindStringSubmatch(rangeHeader); len(m) == 3 {
			startVal, _ := strconv.ParseInt(m[1], 10, 64)
			rS = startVal
			if m[2] != "" {
				endVal, _ := strconv.ParseInt(m[2], 10, 64)
				rE = endVal
			}
			partial = true
		} else if m := rangeSuffixRegex.FindStringSubmatch(rangeHeader); len(m) == 2 {
			suffixLen, _ := strconv.ParseInt(m[1], 10, 64)
			rS = origSz - suffixLen
			if rS < 0 {
				rS = 0
			}
			partial = true
		}
	}

	if rS > rE || rS >= origSz {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", origSz))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	cLen := rE - rS + 1
	contentType := detectMIME(fileName)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(cLen, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")

	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rS, rE, origSz))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if r.Method == http.MethodHead {
		return
	}

	gIV, err := sp.getGlobalIV(reqFPid, fpid)
	if err != nil {
		return
	}

	fi := int(rS / PlainChunkSize)
	li := int(rE / PlainChunkSize)

	for ci := fi; ci <= li; ci++ {
		chunk, err := sp.getDecryptedChunk(reqFPid, fpid, aesKey, origSz, uint64(ci), gIV)
		if err != nil || chunk == nil {
			break
		}

		base := int64(ci) * PlainChunkSize
		a := maxInt64(rS, base) - base
		b := minInt64(rE, base+int64(len(chunk))-1) - base

		if a <= b && a >= 0 && b < int64(len(chunk)) {
			if _, err := w.Write(chunk[a : b+1]); err != nil {
				break
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

func (sp *StreamProxy) getGlobalIV(fPid, fpid string) ([]byte, error) {
	cacheKey := fmt.Sprintf("%s_%s", fPid, fpid)
	sp.cacheMu.Lock()
	if iv, ok := sp.ivCache[cacheKey]; ok {
		sp.cacheMu.Unlock()
		return iv, nil
	}
	sp.cacheMu.Unlock()

	url := fmt.Sprintf("%s/api/media/%s/%s/dat", sp.client.ServerURL, fPid, fpid)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes=0-11")

	resp, err := sp.client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("failed to fetch IV: HTTP %d", resp.StatusCode)
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(resp.Body, iv); err != nil {
		return nil, err
	}

	sp.cacheMu.Lock()
	sp.ivCache[cacheKey] = iv
	sp.cacheMu.Unlock()

	return iv, nil
}

func (sp *StreamProxy) getDecryptedChunk(fPid, fpid string, aesKey []byte, origSz int64, idx uint64, gIV []byte) ([]byte, error) {
	cacheKey := fmt.Sprintf("%s_%s_%d", fPid, fpid, idx)
	sp.cacheMu.Lock()
	if plain, ok := sp.chunkCache[cacheKey]; ok {
		sp.cacheMu.Unlock()
		return plain, nil
	}
	sp.cacheMu.Unlock()

	cS := 12 + int64(idx)*CipherChunkSize
	pLen := PlainChunkSize
	if int64(pLen) > origSz-int64(idx)*PlainChunkSize {
		pLen = int(origSz - int64(idx)*PlainChunkSize)
	}
	cLen := pLen + 16
	cE := cS + int64(cLen) - 1

	url := fmt.Sprintf("%s/api/media/%s/%s/dat", sp.client.ServerURL, fPid, fpid)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", cS, cE))

	resp, err := sp.client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("failed to fetch chunk: HTTP %d", resp.StatusCode)
	}

	cipherBuf := make([]byte, cLen)
	if _, err := io.ReadFull(resp.Body, cipherBuf); err != nil {
		return nil, err
	}

	sm, err := bencrypt.NewSymMaster("gcm1", aesKey)
	if err != nil {
		return nil, err
	}

	plain, err := sm.DecryptChunk(gIV, idx, cipherBuf)
	if err != nil {
		return nil, err
	}

	sp.cacheMu.Lock()
	if len(sp.chunkCache) > 32 { // keep up to 32MB in RAM
		for k := range sp.chunkCache {
			delete(sp.chunkCache, k)
			break
		}
	}
	sp.chunkCache[cacheKey] = plain
	sp.cacheMu.Unlock()

	return plain, nil
}

func detectMIME(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mov":
		return "video/mp4"
	case ".mkv":
		return "video/x-matroska"
	case ".avi":
		return "video/x-msvideo"
	case ".mp3":
		return "audio/mpeg"
	case ".flac":
		return "audio/flac"
	case ".wav":
		return "audio/wav"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain; charset=utf-8"
	default:
		m := mime.TypeByExtension(ext)
		if m != "" {
			return m
		}
		return "application/octet-stream"
	}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
