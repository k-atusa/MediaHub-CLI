package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var passwdCmd = &cobra.Command{
	Use:     "passwd",
	Aliases: []string{"change-password"},
	Short:   "Change account password and re-encrypt personal userdata",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := GetClient()
		if err != nil {
			return err
		}

		oldPw, err := ReadPasswordSecurely("Current password: ")
		if err != nil {
			return err
		}
		if oldPw == "" {
			return errors.New("current password cannot be empty")
		}

		newPw1, err := ReadPasswordSecurely("New password: ")
		if err != nil {
			return err
		}
		if newPw1 == "" {
			return errors.New("new password cannot be empty")
		}

		newPw2, err := ReadPasswordSecurely("Retype new password: ")
		if err != nil {
			return err
		}
		if newPw1 != newPw2 {
			return errors.New("new passwords do not match")
		}

		fmt.Printf("%s[*] Deriving new keys and re-encrypting userdata...%s\n", ColorCyan, ColorReset)
		if err := cli.ChangePassword(oldPw, newPw1); err != nil {
			return err
		}

		fmt.Printf("%s[✓] Password successfully changed! New session saved.%s\n", ColorGreen, ColorReset)
		fmt.Printf("    New User Hash: %s\n", cli.UHash)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(passwdCmd)
}
