package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/k-atusa/mediahub-cli/pkg/bencrypt"
	"github.com/k-atusa/mediahub-cli/pkg/opsec"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:     "info <folderName> [fileName]",
	Aliases: []string{"stat"},
	Short:   "Display cryptographic details and metadata for a folder or file",
	Args:    cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderTarget := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		actualFolderName, fPid, fKey, err := cli.ResolveFolder(folderTarget)
		if err != nil {
			return err
		}

		_, _, flMap, err := cli.GetFiles(actualFolderName)
		if err != nil {
			return err
		}

		if len(args) == 1 {
			var totalFiles int
			var totalSize int64
			for _, info := range flMap {
				if len(info) >= 52 {
					totalFiles++
					totalSize += int64(opsec.DecodeInt(info[44:52]))
				}
			}

			fmt.Printf("\n%sFolder Information:%s\n", ColorBold, ColorReset)
			fmt.Printf("  Name:             %s%s%s\n", ColorCyan, actualFolderName, ColorReset)
			fmt.Printf("  PID:              %s\n", fPid)
			fmt.Printf("  Key (Full 44B):   %s\n", hex.EncodeToString(fKey))
			fmt.Printf("  Total Files:      %d\n", totalFiles)
			fmt.Printf("  Total Size:       %s (%d bytes)\n", FormatBytes(totalSize), totalSize)
			return nil
		}

		fileTarget := args[1]
		actualFileName, fpid, flInfo, err := cli.ResolveFile(flMap, fileTarget)
		if err != nil {
			return err
		}

		fk := flInfo[:44]
		origSz := int64(opsec.DecodeInt(flInfo[44:52]))
		encSz := bencrypt.AfterSize(origSz)
		padSz := opsec.PadLen(encSz)
		totalRemote := encSz + padSz

		fmt.Printf("\n%sFile Cryptographic Details:%s\n", ColorBold, ColorReset)
		fmt.Printf("  Folder:           %s (PID: %s)\n", actualFolderName, fPid)
		fmt.Printf("  File Name:        %s%s%s\n", ColorCyan, actualFileName, ColorReset)
		fmt.Printf("  File PID:         %s\n", fpid)
		fmt.Printf("  File Key (44B):   %s\n", hex.EncodeToString(fk))
		fmt.Printf("  Original Size:    %s (%d bytes)\n", FormatBytes(origSz), origSz)
		fmt.Printf("  Encrypted Size:   %s (%d bytes)\n", FormatBytes(encSz), encSz)
		fmt.Printf("  Obsec Padding:    %s (%d bytes)\n", FormatBytes(padSz), padSz)
		fmt.Printf("  Stored on Server: %s (%d bytes)\n", FormatBytes(totalRemote), totalRemote)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(infoCmd)
}
