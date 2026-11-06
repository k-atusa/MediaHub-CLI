package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
	"github.com/k-atusa/mediahub-cli/pkg/opsec"
)

func (c *Client) GetFiles(folderName string) (string, []byte, map[string][]byte, error) {
	if _, err := c.FetchFolders(); err != nil {
		return "", nil, nil, err
	}
	fKey, exists := c.FldMap[folderName]
	if !exists {
		return "", nil, nil, fmt.Errorf("folder '%s' not found", folderName)
	}
	fPid := c.ObjPid(fKey)

	url := fmt.Sprintf("%s/api/storage/%s/names", c.ServerURL, fPid)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return "", nil, nil, fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	flMap := make(map[string][]byte)
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil, nil, err
		}
		if len(body) > 0 {
			sm, err := bencrypt.NewSymMaster("gcm1", fKey[:32])
			if err != nil {
				return "", nil, nil, err
			}
			decData, err := sm.DeBin(body)
			if err != nil {
				return "", nil, nil, fmt.Errorf("failed to decrypt file list: %w", err)
			}
			flMap, err = opsec.DecodeCfg(decData)
			if err != nil {
				return "", nil, nil, fmt.Errorf("failed to decode file list config: %w", err)
			}
		}
	} else if resp.StatusCode != http.StatusNotFound {
		return "", nil, nil, fmt.Errorf("failed to fetch files: HTTP %d", resp.StatusCode)
	}

	return fPid, fKey, flMap, nil
}

func (c *Client) saveFiles(fPid string, fKey []byte, flMap map[string][]byte) error {
	sm, err := bencrypt.NewSymMaster("gcm1", fKey[:32])
	if err != nil {
		return err
	}
	encMeta, err := sm.EnBin(opsec.EncodeCfg(flMap))
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/storage/%s/names", c.ServerURL, fPid)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encMeta))
	if err != nil {
		return err
	}
	req.Header.Set("X-User-Hash", c.UHash)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to sync file metadata: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) ListFiles(folderName string) ([]FileInfo, error) {
	_, _, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for name, info := range flMap {
		if len(info) < 52 {
			continue
		}
		fk := info[:44]
		origSz := int64(opsec.DecodeInt(info[44:52]))
		fpid := c.ObjPid(fk)

		files = append(files, FileInfo{
			Name: name,
			Size: origSz,
			PID:  fpid,
			Key:  fk,
		})
	}

	return files, nil
}

func (c *Client) UploadFile(folderName string, localPath string, progCb func(sent, total int64, speed float64)) error {
	fInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if fInfo.IsDir() {
		return fmt.Errorf("'%s' is a directory, use directory upload instead", localPath)
	}

	fileName := filepath.Base(localPath)
	origSz := fInfo.Size()

	fPid, fKey, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return err
	}

	fk := append(bencrypt.Random(32), bencrypt.Random(12)...)
	fpid := c.ObjPid(fk)

	smx, err := bencrypt.NewSymMaster("gcmx1", fk[:32])
	if err != nil {
		return err
	}

	encSz := bencrypt.AfterSize(origSz)
	padSz := opsec.PadLen(encSz)
	totalUpload := encSz + padSz

	tmpFile, err := os.CreateTemp("", "mediahub-up-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()

	inFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	if err := smx.EnGCMx(inFile, origSz, tmpFile, nil); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	if padSz > 0 {
		if err := opsec.PadFile(tmpFile, padSz); err != nil {
			return fmt.Errorf("padding failed: %w", err)
		}
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	uploadURL := fmt.Sprintf("%s/api/media/%s/%s/dat", c.ServerURL, fPid, fpid)
	pr := NewProgressReader(tmpFile, totalUpload, progCb)
	req, err := http.NewRequest(http.MethodPost, uploadURL, pr)
	if err != nil {
		return err
	}
	req.ContentLength = totalUpload
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-User-Hash", c.UHash)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload rejected by server: HTTP %d", resp.StatusCode)
	}

	if progCb != nil {
		progCb(totalUpload, totalUpload, 0)
	}

	flMap[fileName] = append(fk, opsec.EncodeInt(uint64(origSz), 8)...)
	return c.saveFiles(fPid, fKey, flMap)
}

func (c *Client) DownloadFile(folderName string, fileName string, outPath string, progCb func(sent, total int64, speed float64)) error {
	fPid, _, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return err
	}

	flInfo, exists := flMap[fileName]
	if !exists {
		return fmt.Errorf("file '%s' not found in folder '%s'", fileName, folderName)
	}

	fk := flInfo[:44]
	origSz := int64(opsec.DecodeInt(flInfo[44:52]))
	fpid := c.ObjPid(fk)

	smx, err := bencrypt.NewSymMaster("gcmx1", fk[:32])
	if err != nil {
		return err
	}
	ciphSz := bencrypt.AfterSize(origSz)

	downURL := fmt.Sprintf("%s/api/media/%s/%s/dat", c.ServerURL, fPid, fpid)
	resp, err := c.HTTPClient.Get(downURL)
	if err != nil {
		return fmt.Errorf("download connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	destFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	pr := NewProgressReader(resp.Body, ciphSz, progCb)
	if err := smx.DeGCMx(pr, ciphSz, destFile, nil); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if progCb != nil {
		progCb(origSz, origSz, 0)
	}
	return nil
}

func (c *Client) DeleteFile(folderName string, fileName string) error {
	fPid, fKey, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return err
	}

	flInfo, exists := flMap[fileName]
	if !exists {
		return fmt.Errorf("file '%s' not found in folder '%s'", fileName, folderName)
	}

	fk := flInfo[:44]
	fpid := c.ObjPid(fk)

	urlDat := fmt.Sprintf("%s/api/media/%s/%s/dat", c.ServerURL, fPid, fpid)
	reqDat, _ := http.NewRequest(http.MethodDelete, urlDat, nil)
	reqDat.Header.Set("X-User-Hash", c.UHash)
	respDat, err := c.HTTPClient.Do(reqDat)
	if err == nil {
		respDat.Body.Close()
	}

	urlThumb := fmt.Sprintf("%s/api/media/%s/%s/thumb", c.ServerURL, fPid, fpid)
	reqThumb, _ := http.NewRequest(http.MethodDelete, urlThumb, nil)
	reqThumb.Header.Set("X-User-Hash", c.UHash)
	respThumb, err := c.HTTPClient.Do(reqThumb)
	if err == nil {
		respThumb.Body.Close()
	}

	delete(flMap, fileName)
	return c.saveFiles(fPid, fKey, flMap)
}

func (c *Client) TrimFolder(folderName string) (string, error) {
	fPid, _, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return "", err
	}

	var pids []string
	for _, info := range flMap {
		if len(info) >= 44 {
			pids = append(pids, c.ObjPid(info[:44]))
		}
	}

	payload, err := json.Marshal(map[string][]string{"pids": pids})
	if err != nil {
		return "", err
	}

	trimURL := fmt.Sprintf("%s/api/trim/%s", c.ServerURL, fPid)
	req, err := http.NewRequest(http.MethodPost, trimURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Hash", c.UHash)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trim failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func (c *Client) CatFile(folderName string, fileName string, dst io.Writer) error {
	fPid, _, flMap, err := c.GetFiles(folderName)
	if err != nil {
		return err
	}

	flInfo, exists := flMap[fileName]
	if !exists {
		return fmt.Errorf("file '%s' not found in folder '%s'", fileName, folderName)
	}

	fk := flInfo[:44]
	origSz := int64(opsec.DecodeInt(flInfo[44:52]))
	fpid := c.ObjPid(fk)

	smx, err := bencrypt.NewSymMaster("gcmx1", fk[:32])
	if err != nil {
		return err
	}
	ciphSz := bencrypt.AfterSize(origSz)

	downURL := fmt.Sprintf("%s/api/media/%s/%s/dat", c.ServerURL, fPid, fpid)
	resp, err := c.HTTPClient.Get(downURL)
	if err != nil {
		return fmt.Errorf("download connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	return smx.DeGCMx(resp.Body, ciphSz, dst, nil)
}

func (c *Client) GetNotice() (string, error) {
	url := fmt.Sprintf("%s/api/notice", c.ServerURL)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch notice: HTTP %d", resp.StatusCode)
	}

	var data struct {
		Notice string `json:"notice"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Notice, nil
}
