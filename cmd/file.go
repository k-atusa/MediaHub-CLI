package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/k-atusa/mediahub-cli/pkg/client"
	"github.com/spf13/cobra"
)

var (
	downloadOutDir  string
	downloadOutFile string
	uploadRecursive bool
)

var fileCmd = &cobra.Command{
	Use:     "file",
	Aliases: []string{"fl"},
	Short:   "Manage encrypted files (list, upload, download, delete, trim)",
}

var fileListCmd = &cobra.Command{
	Use:     "list <folderName>",
	Aliases: []string{"ls"},
	Short:   "List all files in an encrypted folder",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		files, err := cli.ListFiles(folderName)
		if err != nil {
			return err
		}

		if len(files) == 0 {
			fmt.Printf("Folder '%s' is empty.\n", folderName)
			return nil
		}

		sort.Slice(files, func(i, j int) bool {
			return files[i].Name < files[j].Name
		})

		cols := []TableColumn{
			{Header: "File Name", Align: AlignLeft, Flex: true, MinWidth: 24},
			{Header: "Size", Align: AlignRight, MinWidth: 10, TextColor: ColorYellow},
			{Header: "File PID", Align: AlignLeft, MinWidth: 24, MaxWidth: 24, TextColor: ColorGray},
		}
		var rows [][]string
		var totalSize int64 = 0
		for _, f := range files {
			totalSize += f.Size
			icon := FileTypeIcon(f.Name)
			displayName := fmt.Sprintf("%s %s", icon, f.Name)
			rows = append(rows, []string{
				displayName,
				FormatBytes(f.Size),
				f.PID,
			})
		}

		RenderResponsiveTable(cols, rows)
		fmt.Printf("\n%sTotal: %d files (%s)%s\n", ColorDim, len(files), FormatBytes(totalSize), ColorReset)
		return nil
	},
}

var fileUploadCmd = &cobra.Command{
	Use:     "upload <folderName> <path...>",
	Aliases: []string{"put", "up"},
	Short:   "Encrypt and upload one or more files or directories",
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		targetPaths := args[1:]

		cli, err := GetClient()
		if err != nil {
			return err
		}

		for _, target := range targetPaths {
			info, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("cannot read '%s': %w", target, err)
			}

			if info.IsDir() {
				err = filepath.WalkDir(target, func(p string, d fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if d.IsDir() {
						return nil
					}
					return uploadSingleFile(cli, folderName, p)
				})
				if err != nil {
					return err
				}
			} else {
				if err := uploadSingleFile(cli, folderName, target); err != nil {
					return err
				}
			}
		}

		fmt.Printf("%s[✓] All uploads completed successfully!%s\n", ColorGreen, ColorReset)
		return nil
	},
}

func uploadSingleFile(cli *client.Client, folderName, localPath string) error {
	baseName := filepath.Base(localPath)
	fmt.Printf("%s[*] Encrypting & uploading '%s'...%s\n", ColorCyan, baseName, ColorReset)

	cb := func(sent, total int64, speed float64) {
		RenderProgressBar(baseName, sent, total, speed)
	}

	if err := cli.UploadFile(folderName, localPath, cb); err != nil {
		fmt.Printf("\n%s[✗] Upload failed for '%s': %v%s\n", ColorRed, baseName, err, ColorReset)
		return err
	}
	fmt.Printf("%s[✓] Uploaded '%s'%s\n", ColorGreen, baseName, ColorReset)
	return nil
}

var fileDownloadCmd = &cobra.Command{
	Use:     "download <folderName> <fileName>",
	Aliases: []string{"get", "down"},
	Short:   "Download and decrypt a file from the server",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		fileName := args[1]

		cli, err := GetClient()
		if err != nil {
			return err
		}

		outPath := downloadOutFile
		if outPath == "" {
			if downloadOutDir != "" {
				outPath = filepath.Join(downloadOutDir, fileName)
			} else {
				outPath = fileName
			}
		}

		fmt.Printf("%s[*] Downloading & decrypting '%s' -> '%s'...%s\n", ColorCyan, fileName, outPath, ColorReset)
		cb := func(sent, total int64, speed float64) {
			RenderProgressBar(fileName, sent, total, speed)
		}

		if err := cli.DownloadFile(folderName, fileName, outPath, cb); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}

		fmt.Printf("%s[✓] Successfully downloaded '%s'!%s\n", ColorGreen, outPath, ColorReset)
		return nil
	},
}

var fileDownloadAllCmd = &cobra.Command{
	Use:     "download-all <folderName>",
	Aliases: []string{"get-all"},
	Short:   "Download and decrypt all files in a folder",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		files, err := cli.ListFiles(folderName)
		if err != nil {
			return err
		}

		targetDir := downloadOutDir
		if targetDir == "" {
			targetDir = folderName
		}
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return err
		}

		fmt.Printf("%s[*] Downloading %d files into '%s'...%s\n", ColorCyan, len(files), targetDir, ColorReset)
		for i, f := range files {
			fmt.Printf("[%d/%d] %s (%s)\n", i+1, len(files), f.Name, FormatBytes(f.Size))
			outPath := filepath.Join(targetDir, f.Name)
			cb := func(sent, total int64, speed float64) {
				RenderProgressBar(f.Name, sent, total, speed)
			}
			if err := cli.DownloadFile(folderName, f.Name, outPath, cb); err != nil {
				fmt.Printf("%s[✗] Failed to download '%s': %v%s\n", ColorRed, f.Name, err, ColorReset)
			}
		}

		fmt.Printf("%s[✓] Download finished.%s\n", ColorGreen, ColorReset)
		return nil
	},
}

var fileDeleteCmd = &cobra.Command{
	Use:     "delete <folderName> <fileName>",
	Aliases: []string{"rm"},
	Short:   "Delete an encrypted file from a folder",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		fileName := args[1]

		cli, err := GetClient()
		if err != nil {
			return err
		}

		if err := cli.DeleteFile(folderName, fileName); err != nil {
			return err
		}

		fmt.Printf("%s[✓] File '%s' deleted from '%s'.%s\n", ColorGreen, fileName, folderName, ColorReset)
		return nil
	},
}

var fileTrimCmd = &cobra.Command{
	Use:   "trim <folderName>",
	Short: "Clean up orphan encrypted data blocks in a folder on the server",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		res, err := cli.TrimFolder(folderName)
		if err != nil {
			return err
		}

		fmt.Printf("%s[✓] Trim executed: %s%s\n", ColorGreen, res, ColorReset)
		return nil
	},
}

var fileCatCmd = &cobra.Command{
	Use:     "cat <folderName> <fileName>",
	Aliases: []string{"view"},
	Short:   "Decrypt and print file contents directly to standard output",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		fileName := args[1]

		cli, err := GetClient()
		if err != nil {
			return err
		}

		return cli.CatFile(folderName, fileName, os.Stdout)
	},
}

func init() {
	fileDownloadCmd.Flags().StringVarP(&downloadOutFile, "out", "o", "", "Destination file path")
	fileDownloadCmd.Flags().StringVarP(&downloadOutDir, "dir", "d", "", "Destination directory")
	fileDownloadAllCmd.Flags().StringVarP(&downloadOutDir, "out", "o", "", "Destination directory")

	fileCmd.AddCommand(fileListCmd)
	fileCmd.AddCommand(fileUploadCmd)
	fileCmd.AddCommand(fileDownloadCmd)
	fileCmd.AddCommand(fileDownloadAllCmd)
	fileCmd.AddCommand(fileDeleteCmd)
	fileCmd.AddCommand(fileTrimCmd)
	fileCmd.AddCommand(fileCatCmd)

	RootCmd.AddCommand(fileCmd)
	RootCmd.AddCommand(fileUploadCmd)
	RootCmd.AddCommand(fileDownloadCmd)
	RootCmd.AddCommand(fileDownloadAllCmd)
	RootCmd.AddCommand(fileDeleteCmd)
	RootCmd.AddCommand(fileTrimCmd)
	RootCmd.AddCommand(fileCatCmd)
}
