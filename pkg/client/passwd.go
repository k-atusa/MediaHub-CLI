package client

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"github.com/k-atusa/mediahub-cli/pkg/bencode"
	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
	"github.com/k-atusa/mediahub-cli/pkg/opsec"
)

func (c *Client) ChangePassword(oldPassword, newPassword string) error {
	if c.Username == "" || c.UHash == "" {
		return errors.New("not authenticated: run login first")
	}

	testCli := NewClient(c.ServerURL, c.Username, oldPassword, c.InsecureTLS)
	if err := testCli.Auth(); err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}
	if testCli.UHash != c.UHash {
		return errors.New("current password does not match active session")
	}

	if _, err := c.FetchFolders(); err != nil {
		return fmt.Errorf("failed to load current userdata: %w", err)
	}

	newSalt := bencrypt.SHA3256([]byte(c.Username + Pepper))
	newPw := bencode.NormPW(newPassword)

	hm, err := bencrypt.NewHashMaster("arg2st", 32, 32)
	if err != nil {
		return err
	}

	newStKey, newUKey, err := hm.KDF(newPw, newSalt)
	if err != nil {
		return err
	}

	newUHash := c.UsrPid(newStKey)
	newKey := newUKey[:32]

	sm, err := bencrypt.NewSymMaster("gcm1", newKey)
	if err != nil {
		return err
	}

	encData, err := sm.EnBin(opsec.EncodeCfg(c.FldMap))
	if err != nil {
		return err
	}

	postURL := fmt.Sprintf("%s/api/userdata/%s", c.ServerURL, newUHash)
	req, err := http.NewRequest(http.MethodPost, postURL, bytes.NewReader(encData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Old-Hash", c.UHash)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("password change rejected by server: HTTP %d", resp.StatusCode)
	}

	delURL := fmt.Sprintf("%s/api/userdata/%s", c.ServerURL, c.UHash)
	delReq, err := http.NewRequest(http.MethodDelete, delURL, nil)
	if err == nil {
		if delResp, err := c.HTTPClient.Do(delReq); err == nil {
			delResp.Body.Close()
		}
	}

	c.UHash = newUHash
	c.UKey = newKey
	c.Password = newPassword

	return c.SaveSession()
}
