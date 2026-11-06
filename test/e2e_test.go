package test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k-atusa/mediahub-cli/pkg/client"
	"github.com/k-atusa/mediahub-cli/pkg/proxy"
)

// MockMediaHubServer simulates the MediaHub server API in-memory.
type MockMediaHubServer struct {
	mu       sync.Mutex
	userdata map[string][]byte
	storage  map[string]map[string][]byte // folderPid -> "names" -> data
	media    map[string][]byte            // "folderPid/filePid/type" -> data
	ts       *httptest.Server
}

func newMockServer() *MockMediaHubServer {
	s := &MockMediaHubServer{
		userdata: make(map[string][]byte),
		storage:  make(map[string]map[string][]byte),
		media:    make(map[string][]byte),
	}

	mux := http.NewServeMux()

	// Userdata endpoint
	mux.HandleFunc("/api/userdata/", func(w http.ResponseWriter, r *http.Request) {
		uHash := strings.TrimPrefix(r.URL.Path, "/api/userdata/")
		s.mu.Lock()
		defer s.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			if data, ok := s.userdata[uHash]; ok {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusOK) // Return empty if new
			}
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			s.userdata[uHash] = body
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		}
	})

	// Storage names endpoint
	mux.HandleFunc("/api/storage/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/storage/"), "/")
		if len(parts) < 2 {
			http.Error(w, "bad request", 400)
			return
		}
		fPid, metaType := parts[0], parts[1]
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.storage[fPid] == nil {
			s.storage[fPid] = make(map[string][]byte)
		}

		switch r.Method {
		case http.MethodGet:
			if data, ok := s.storage[fPid][metaType]; ok {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			s.storage[fPid][metaType] = body
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		case http.MethodDelete:
			delete(s.storage, fPid)
			w.WriteHeader(http.StatusOK)
		}
	})

	// Media endpoint
	mux.HandleFunc("/api/media/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/media/"), "/")
		if len(parts) < 3 {
			http.Error(w, "bad request", 400)
			return
		}
		fPid, filePid, dataType := parts[0], parts[1], parts[2]
		key := fmt.Sprintf("%s/%s/%s", fPid, filePid, dataType)

		s.mu.Lock()
		defer s.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			data, ok := s.media[key]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			http.ServeContent(w, r, filePid+"."+dataType, time.Now(), bytes.NewReader(data))
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			s.media[key] = body
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		case http.MethodDelete:
			delete(s.media, key)
			w.WriteHeader(http.StatusOK)
		}
	})

	s.ts = httptest.NewServer(mux)
	return s
}

func TestE2ELifecycle(t *testing.T) {
	srv := newMockServer()
	defer srv.ts.Close()

	// 1. Initialize client and authenticate
	cli := client.NewClient(srv.ts.URL, "alice", "SecretPassword2026!", true)
	if err := cli.Auth(); err != nil {
		t.Fatalf("Auth failed: %v", err)
	}

	// 2. Create encrypted folder
	folderName := "TestVideos"
	if err := cli.CreateFolder(folderName); err != nil {
		t.Fatalf("CreateFolder failed: %v", err)
	}

	// 3. Prepare dummy video file (3MB of data to test multiple GCMx chunks)
	tmpDir := t.TempDir()
	sampleVideoPath := filepath.Join(tmpDir, "sample.mp4")
	sampleContent := bytes.Repeat([]byte("0123456789ABCDEF"), 200*1024) // 3.2MB
	if err := os.WriteFile(sampleVideoPath, sampleContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 4. Upload file
	var lastSent, lastTotal int64
	err := cli.UploadFile(folderName, sampleVideoPath, func(sent, total int64, speed float64) {
		lastSent = sent
		lastTotal = total
	})
	if err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}
	if lastSent != lastTotal || lastTotal == 0 {
		t.Fatalf("Upload progress did not complete: %d / %d", lastSent, lastTotal)
	}

	// 5. List files
	files, err := cli.ListFiles(folderName)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "sample.mp4" {
		t.Fatalf("Unexpected file list: %+v", files)
	}
	if files[0].Size != int64(len(sampleContent)) {
		t.Fatalf("Original size mismatch: expected %d, got %d", len(sampleContent), files[0].Size)
	}

	// 6. Download file and verify byte equality
	downloadPath := filepath.Join(tmpDir, "downloaded.mp4")
	err = cli.DownloadFile(folderName, "sample.mp4", downloadPath, nil)
	if err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}
	downBytes, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("Read downloaded file failed: %v", err)
	}
	if !bytes.Equal(sampleContent, downBytes) {
		t.Fatalf("Downloaded content does not match original!")
	}

	// 7. Test Streaming Proxy with Range Seeking
	fPid, _, flMap, err := cli.GetFiles(folderName)
	if err != nil {
		t.Fatalf("GetFiles failed: %v", err)
	}
	stProxy := proxy.NewStreamProxy(cli, 0)
	stProxy.UpdateContext(fPid, flMap)
	port, err := stProxy.Start()
	if err != nil {
		t.Fatalf("StreamProxy start failed: %v", err)
	}
	defer stProxy.Stop()

	streamURL := stProxy.StreamURL(fPid, "sample.mp4")
	if !strings.Contains(streamURL, fmt.Sprintf("%d", port)) {
		t.Fatalf("Stream URL port mismatch: %s", streamURL)
	}

	// Request Range bytes=1500000-2500000 (crossing chunk boundaries!)
	req, _ := http.NewRequest(http.MethodGet, streamURL, nil)
	req.Header.Set("Range", "bytes=1500000-2500000")
	pClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := pClient.Do(req)
	if err != nil {
		t.Fatalf("Proxy stream request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("Expected 206 Partial Content, got %d", resp.StatusCode)
	}

	streamedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading stream body failed: %v", err)
	}

	expectedSlice := sampleContent[1500000 : 2500000+1]
	if !bytes.Equal(expectedSlice, streamedBytes) {
		t.Fatalf("Streamed Range slice does not match expected slice! len exp=%d, got=%d", len(expectedSlice), len(streamedBytes))
	}

	// 8. Test Share Token export and import by Bob
	shareToken, err := cli.ExportShare(folderName, "BobSharePass123")
	if err != nil {
		t.Fatalf("ExportShare failed: %v", err)
	}

	bobCli := client.NewClient(srv.ts.URL, "bob", "BobMasterPW99!", true)
	if err := bobCli.Auth(); err != nil {
		t.Fatalf("Bob auth failed: %v", err)
	}
	importedFolderName, err := bobCli.ImportShare(shareToken, "BobSharePass123")
	if err != nil {
		t.Fatalf("ImportShare failed: %v", err)
	}
	if importedFolderName != folderName {
		t.Fatalf("Imported folder name mismatch: expected %s, got %s", folderName, importedFolderName)
	}

	// Bob can list files in shared folder
	bobFiles, err := bobCli.ListFiles(importedFolderName)
	if err != nil {
		t.Fatalf("Bob ListFiles failed: %v", err)
	}
	if len(bobFiles) != 1 || bobFiles[0].Name != "sample.mp4" {
		t.Fatalf("Bob could not see shared file: %+v", bobFiles)
	}

	// 9. Bob unlinks folder
	if err := bobCli.UnlinkFolder(importedFolderName); err != nil {
		t.Fatalf("Bob UnlinkFolder failed: %v", err)
	}

	// Alice deletes file
	if err := cli.DeleteFile(folderName, "sample.mp4"); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	filesAfterDelete, _ := cli.ListFiles(folderName)
	if len(filesAfterDelete) != 0 {
		t.Fatalf("Expected 0 files after delete, got %d", len(filesAfterDelete))
	}
}
