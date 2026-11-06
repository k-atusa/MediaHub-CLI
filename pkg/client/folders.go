package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
	"github.com/k-atusa/mediahub-cli/pkg/opsec"
)

func (c *Client) FetchFolders() (map[string][]byte, error) {
	if c.UHash == "" {
		return nil, errors.New("not authenticated: run login or auth first")
	}

	url := fmt.Sprintf("%s/api/userdata/%s", c.ServerURL, c.UHash)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if len(body) > 0 {
			sm, err := bencrypt.NewSymMaster("gcm1", c.UKey[:32])
			if err != nil {
				return nil, err
			}
			decData, err := sm.DeBin(body)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt user data: %w", err)
			}
			fldMap, err := opsec.DecodeCfg(decData)
			if err != nil {
				return nil, fmt.Errorf("failed to decode user data config: %w", err)
			}
			c.FldMap = fldMap
		} else {
			c.FldMap = make(map[string][]byte)
		}
	} else if resp.StatusCode == http.StatusNotFound {
		c.FldMap = make(map[string][]byte)
	} else {
		return nil, fmt.Errorf("server error: HTTP %d", resp.StatusCode)
	}

	return c.FldMap, nil
}

func (c *Client) saveFolders() error {
	if c.UHash == "" {
		return errors.New("not authenticated")
	}

	sm, err := bencrypt.NewSymMaster("gcm1", c.UKey[:32])
	if err != nil {
		return err
	}

	encData, err := sm.EnBin(opsec.EncodeCfg(c.FldMap))
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/userdata/%s", c.ServerURL, c.UHash)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to save folders: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CreateFolder(name string) error {
	if _, err := c.FetchFolders(); err != nil {
		return err
	}

	if _, exists := c.FldMap[name]; exists {
		return fmt.Errorf("folder '%s' already exists", name)
	}

	fKey := append(bencrypt.Random(32), bencrypt.Random(12)...)
	c.FldMap[name] = fKey

	if err := c.saveFolders(); err != nil {
		return err
	}

	fPid := c.ObjPid(fKey)
	emptyFlMap := make(map[string][]byte)
	sm, err := bencrypt.NewSymMaster("gcm1", fKey[:32])
	if err != nil {
		return err
	}
	encMeta, err := sm.EnBin(opsec.EncodeCfg(emptyFlMap))
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
		return fmt.Errorf("failed to initialize folder storage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to initialize folder storage: HTTP %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) UnlinkFolder(name string) error {
	if _, err := c.FetchFolders(); err != nil {
		return err
	}
	if _, exists := c.FldMap[name]; !exists {
		return fmt.Errorf("folder '%s' not found", name)
	}

	delete(c.FldMap, name)
	return c.saveFolders()
}

func (c *Client) DeleteFolder(name string) error {
	if _, err := c.FetchFolders(); err != nil {
		return err
	}
	fKey, exists := c.FldMap[name]
	if !exists {
		return fmt.Errorf("folder '%s' not found", name)
	}

	fPid := c.ObjPid(fKey)

	url := fmt.Sprintf("%s/api/storage/%s/names", c.ServerURL, fPid)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-User-Hash", c.UHash)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete folder storage on server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete folder on server: HTTP %d", resp.StatusCode)
	}

	delete(c.FldMap, name)
	return c.saveFolders()
}

func (c *Client) ExportShare(name string, password string) (string, error) {
	if _, err := c.FetchFolders(); err != nil {
		return "", err
	}
	fKey, exists := c.FldMap[name]
	if !exists {
		return "", fmt.Errorf("folder '%s' not found", name)
	}

	return opsec.ExportShareToken(name, fKey, password)
}

func (c *Client) ImportShare(tokenText string, password string) (string, error) {
	fName, fKey, err := opsec.ImportShareToken(tokenText, password)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt share token: %w", err)
	}

	if _, err := c.FetchFolders(); err != nil {
		return "", err
	}

	targetName := fName
	counter := 1
	for {
		if _, exists := c.FldMap[targetName]; !exists {
			break
		}
		targetName = fmt.Sprintf("%s_%d", fName, counter)
		counter++
	}

	c.FldMap[targetName] = fKey
	if err := c.saveFolders(); err != nil {
		return "", err
	}

	return targetName, nil
}
