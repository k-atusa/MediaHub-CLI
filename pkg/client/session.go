package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type SessionConfig struct {
	ServerURL   string `json:"server_url"`
	Username    string `json:"username"`
	UHash       string `json:"uhash"`
	UKeyHex     string `json:"ukey_hex"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func ConfigFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mediahub", "config.json"), nil
}

func (c *Client) SaveSession() error {
	cfgPath, err := ConfigFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		return err
	}

	cfg := SessionConfig{
		ServerURL:   c.ServerURL,
		Username:    c.Username,
		UHash:       c.UHash,
		UKeyHex:     hex.EncodeToString(c.UKey),
		InsecureTLS: c.InsecureTLS,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cfgPath, data, 0600)
}

func LoadSavedSession() (*Client, error) {
	cfgPath, err := ConfigFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("no active session: please run 'mediahub login' first")
		}
		return nil, err
	}

	var cfg SessionConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("corrupted session config: %w", err)
	}

	uKey, err := hex.DecodeString(cfg.UKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid stored key: %w", err)
	}

	cli := NewClient(cfg.ServerURL, cfg.Username, "", cfg.InsecureTLS)
	cli.SetAuth(cfg.UHash, uKey)
	return cli, nil
}

func ClearSession() error {
	cfgPath, err := ConfigFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(cfgPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func HasActiveSession() bool {
	cfgPath, err := ConfigFilePath()
	if err != nil {
		return false
	}
	info, err := os.Stat(cfgPath)
	return err == nil && !info.IsDir()
}
