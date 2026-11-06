package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	sharePassword string
	shareOutFile  string
	importPassword string
	confirmDelete bool
)

var folderCmd = &cobra.Command{
	Use:     "folder",
	Aliases: []string{"fld"},
	Short:   "Manage encrypted folders (create, list, delete, unlink, share, import)",
}

var folderListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all decrypted folders in your account",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := GetClient()
		if err != nil {
			return err
		}

		flds, err := cli.FetchFolders()
		if err != nil {
			return err
		}

		if len(flds) == 0 {
			fmt.Println("No folders found. Create one with 'mediahub mkdir <name>'")
			return nil
		}

		var names []string
		for name := range flds {
			names = append(names, name)
		}
		sort.Strings(names)

		headers := []string{"Folder Name", "Folder PID", "Key Prefix"}
		var rows [][]string
		for _, name := range names {
			key := flds[name]
			pid := cli.ObjPid(key)
			keyPrefix := fmt.Sprintf("%x...", key[:6])
			rows = append(rows, []string{name, pid, keyPrefix})
		}

		PrintTable(headers, rows)
		return nil
	},
}

var folderCreateCmd = &cobra.Command{
	Use:     "create <folderName>",
	Aliases: []string{"mkdir", "mk"},
	Short:   "Create a new encrypted folder",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		if err := cli.CreateFolder(folderName); err != nil {
			return err
		}

		fmt.Printf("%s[✓] Folder '%s' successfully created and synchronized with server.%s\n", ColorGreen, folderName, ColorReset)
		return nil
	},
}

var folderUnlinkCmd = &cobra.Command{
	Use:     "unlink <folderName>",
	Short:   "Unlink a shared folder from your account (safe: retains server storage)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		if err := cli.UnlinkFolder(folderName); err != nil {
			return err
		}

		fmt.Printf("%s[✓] Folder '%s' has been unlinked from your account.%s\n", ColorGreen, folderName, ColorReset)
		return nil
	},
}

var folderDeleteCmd = &cobra.Command{
	Use:     "delete <folderName>",
	Aliases: []string{"rmdir", "rm"},
	Short:   "Permanently destroy a folder and its contents on the server",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		if !confirmDelete {
			fmt.Printf("%s[!] WARNING: This will permanently wipe all encrypted files and metadata for folder '%s' from the server.%s\n", ColorYellow, folderName, ColorReset)
			fmt.Print("Are you sure? Enter folder name to confirm: ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			if strings.TrimSpace(input) != folderName {
				fmt.Println("Aborted: folder name does not match.")
				return nil
			}
		}

		if err := cli.DeleteFolder(folderName); err != nil {
			return err
		}

		fmt.Printf("%s[✓] Folder '%s' and its remote files were permanently deleted.%s\n", ColorGreen, folderName, ColorReset)
		return nil
	},
}

var folderShareCmd = &cobra.Command{
	Use:     "share <folderName>",
	Short:   "Generate an encrypted share token for a folder",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		pw := sharePassword
		if pw == "" {
			var err error
			pw, err = ReadPasswordSecurely("Enter password to protect share token: ")
			if err != nil {
				return err
			}
			if pw == "" {
				return fmt.Errorf("password cannot be empty")
			}
		}

		token, err := cli.ExportShare(folderName, pw)
		if err != nil {
			return err
		}

		if shareOutFile != "" {
			if err := os.WriteFile(shareOutFile, []byte(token), 0600); err != nil {
				return fmt.Errorf("failed to save share token to %s: %w", shareOutFile, err)
			}
			fmt.Printf("%s[✓] Share token saved to '%s'%s\n", ColorGreen, shareOutFile, ColorReset)
		} else {
			fmt.Printf("\n%s--- MediaHub Share Token for '%s' ---%s\n", ColorCyan, folderName, ColorReset)
			fmt.Println(token)
			fmt.Printf("%s----------------------------------------%s\n", ColorCyan, ColorReset)
			fmt.Println("Anyone with this token and the share password can access this folder.")
		}
		return nil
	},
}

var folderImportCmd = &cobra.Command{
	Use:     "import <token-or-file>",
	Short:   "Import an encrypted share token to access a shared folder",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		tokenContent := target
		if _, err := os.Stat(target); err == nil {
			data, err := os.ReadFile(target)
			if err != nil {
				return fmt.Errorf("failed to read token file: %w", err)
			}
			tokenContent = string(data)
		}

		pw := importPassword
		if pw == "" {
			var err error
			pw, err = ReadPasswordSecurely("Enter share password: ")
			if err != nil {
				return err
			}
		}

		importedName, err := cli.ImportShare(tokenContent, pw)
		if err != nil {
			return err
		}

		fmt.Printf("%s[✓] Successfully imported folder as '%s'!%s\n", ColorGreen, importedName, ColorReset)
		return nil
	},
}

// Top-level aliases for convenient fast typing:
var lsCmd = &cobra.Command{
	Use:   "ls [folderName]",
	Short: "List folders or files inside a folder",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return folderListCmd.RunE(cmd, args)
		}
		return fileListCmd.RunE(cmd, args)
	},
}

var mkdirCmd = &cobra.Command{
	Use:   "mkdir <folderName>",
	Short: "Create a new encrypted folder",
	Args:  cobra.ExactArgs(1),
	RunE:  folderCreateCmd.RunE,
}

var rmdirCmd = &cobra.Command{
	Use:   "rmdir <folderName>",
	Short: "Permanently delete a folder",
	Args:  cobra.ExactArgs(1),
	RunE:  folderDeleteCmd.RunE,
}

func init() {
	folderDeleteCmd.Flags().BoolVarP(&confirmDelete, "yes", "y", false, "Skip deletion confirmation prompt")
	folderShareCmd.Flags().StringVarP(&sharePassword, "password", "p", "", "Password to encrypt the share token")
	folderShareCmd.Flags().StringVarP(&shareOutFile, "out", "o", "", "Output file path to write token")
	folderImportCmd.Flags().StringVarP(&importPassword, "password", "p", "", "Password to decrypt the share token")

	folderCmd.AddCommand(folderListCmd)
	folderCmd.AddCommand(folderCreateCmd)
	folderCmd.AddCommand(folderUnlinkCmd)
	folderCmd.AddCommand(folderDeleteCmd)
	folderCmd.AddCommand(folderShareCmd)
	folderCmd.AddCommand(folderImportCmd)

	RootCmd.AddCommand(folderCmd)
	RootCmd.AddCommand(lsCmd)
	RootCmd.AddCommand(mkdirCmd)
	RootCmd.AddCommand(rmdirCmd)
	RootCmd.AddCommand(folderShareCmd)
	RootCmd.AddCommand(folderImportCmd)
}
