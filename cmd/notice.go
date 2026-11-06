package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var noticeCmd = &cobra.Command{
	Use:   "notice",
	Short: "Fetch and display public server notification",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := GetClient()
		if err != nil {
			return err
		}

		notice, err := cli.GetNotice()
		if err != nil {
			return err
		}

		if notice == "" {
			fmt.Println("No public notice posted on server.")
			return nil
		}

		fmt.Printf("\n%s--- Server Notice ---%s\n", ColorCyan, ColorReset)
		fmt.Println(notice)
		fmt.Printf("%s---------------------%s\n", ColorCyan, ColorReset)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(noticeCmd)
}
