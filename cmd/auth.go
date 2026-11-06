package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/k-atusa/mediahub-cli/pkg/client"
	"github.com/spf13/cobra"
)

var (
	loginServer   string
	loginUser     string
	loginPassword string
	loginInsecure bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a MediaHub server and save the session locally",
	RunE: func(cmd *cobra.Command, args []string) error {
		reader := bufio.NewReader(os.Stdin)

		server := loginServer
		if server == "" {
			server = flagServerURL
		}
		if server == "" {
			fmt.Print("Server URL (e.g. https://localhost:443): ")
			text, _ := reader.ReadString('\n')
			server = strings.TrimSpace(text)
		}
		if server == "" {
			return fmt.Errorf("server URL is required")
		}

		user := loginUser
		if user == "" {
			user = flagUsername
		}
		if user == "" {
			fmt.Print("Username: ")
			text, _ := reader.ReadString('\n')
			user = strings.TrimSpace(text)
		}
		if user == "" {
			return fmt.Errorf("username is required")
		}

		pw := loginPassword
		if pw == "" {
			pw = flagPassword
		}
		if pw == "" {
			var err error
			pw, err = ReadPasswordSecurely("Password: ")
			if err != nil {
				return err
			}
		}

		insecure := loginInsecure || flagInsecureTLS

		fmt.Printf("%s[+] Deriving Zero-Knowledge keys with Argon2id...%s\n", ColorCyan, ColorReset)
		cli := client.NewClient(server, user, pw, insecure)
		if err := cli.Auth(); err != nil {
			return fmt.Errorf("key derivation failed: %w", err)
		}

		// Verify credentials against server by attempting to fetch userdata
		fmt.Printf("%s[+] Verifying credentials with %s...%s\n", ColorCyan, server, ColorReset)
		flds, err := cli.FetchFolders()
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		if err := cli.SaveSession(); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}

		fmt.Printf("%s[✓] Successfully authenticated as '%s'!%s\n", ColorGreen, user, ColorReset)
		fmt.Printf("    Server: %s\n", server)
		fmt.Printf("    User Hash: %s\n", cli.UHash)
		fmt.Printf("    Decrypted Folders: %d\n", len(flds))
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear the saved local authentication session",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := client.ClearSession(); err != nil {
			return fmt.Errorf("failed to clear session: %w", err)
		}
		fmt.Printf("%s[✓] Session cleared successfully.%s\n", ColorGreen, ColorReset)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"whoami"},
	Short:   "Show current session status, user hash, and server connectivity",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := client.LoadSavedSession()
		if err != nil {
			fmt.Printf("%s[-] No active session: %v%s\n", ColorYellow, err, ColorReset)
			return nil
		}

		fmt.Printf("%sMediaHub Active Session:%s\n", ColorBold, ColorReset)
		fmt.Printf("  Server:    %s\n", cli.ServerURL)
		fmt.Printf("  Username:  %s\n", cli.Username)
		fmt.Printf("  User Hash: %s\n", cli.UHash)
		fmt.Printf("  Insecure:  %v\n", cli.InsecureTLS)

		flds, err := cli.FetchFolders()
		if err != nil {
			fmt.Printf("  Status:    %sOffline / Server Error: %v%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("  Status:    %sConnected (Found %d folders)%s\n", ColorGreen, len(flds), ColorReset)
		}

		return nil
	},
}

func init() {
	loginCmd.Flags().StringVarP(&loginServer, "server", "s", "", "MediaHub server URL")
	loginCmd.Flags().StringVarP(&loginUser, "user", "u", "", "Username")
	loginCmd.Flags().StringVarP(&loginPassword, "password", "p", "", "Password")
	loginCmd.Flags().BoolVarP(&loginInsecure, "insecure", "k", false, "Skip TLS verification")

	RootCmd.AddCommand(loginCmd)
	RootCmd.AddCommand(logoutCmd)
	RootCmd.AddCommand(statusCmd)
}
