package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/k-atusa/mediahub-cli/pkg/client"
	"github.com/spf13/cobra"
)

var (
	flagServerURL   string
	flagUsername    string
	flagPassword    string
	flagInsecureTLS bool
)

var RootCmd = &cobra.Command{
	Use:   "mediahub",
	Short: "MediaHub CLI: Zero-Trust Encrypted File Sharing & Media Streaming Platform",
	Long: `MediaHub CLI is an enterprise-grade command-line interface for the MediaHub 
zero-knowledge, end-to-end encrypted (E2EE) file sharing and video streaming platform.

Features:
  - Client-side Argon2id key derivation & Zero-Trust zero-knowledge architecture
  - AES-256-GCM authenticated encryption with traffic-analysis obfuscation padding
  - Real-time on-demand media streaming proxy with HTTP Range seeking support
  - Cross-platform shared folder tokens with password protection
  - Seamless directory batch uploading and downloading`,
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&flagServerURL, "server", "s", "", "MediaHub server URL (e.g. https://localhost:443)")
	RootCmd.PersistentFlags().StringVarP(&flagUsername, "user", "u", "", "Username for authentication")
	RootCmd.PersistentFlags().StringVarP(&flagPassword, "password", "p", "", "Password for authentication")
	RootCmd.PersistentFlags().BoolVarP(&flagInsecureTLS, "insecure", "k", false, "Skip TLS certificate verification (for self-signed certs)")
}

func GetClient() (*client.Client, error) {

	if flagServerURL != "" && flagUsername != "" {
		pw := flagPassword
		if pw == "" {
			var err error
			pw, err = ReadPasswordSecurely("Enter password: ")
			if err != nil {
				return nil, err
			}
		}
		cli := client.NewClient(flagServerURL, flagUsername, pw, flagInsecureTLS)
		if err := cli.Auth(); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		return cli, nil
	}

	cli, err := client.LoadSavedSession()
	if err != nil {
		return nil, errors.New("not logged in. Please run 'mediahub login' or provide --server and --user flags")
	}

	if flagServerURL != "" {
		cli.ServerURL = flagServerURL
	}
	if flagInsecureTLS {
		cli.InsecureTLS = true
		if tr, ok := cli.HTTPClient.Transport.(*http.Transport); ok {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	return cli, nil
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
}
