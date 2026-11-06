package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"syscall"

	"github.com/k-atusa/mediahub-cli/pkg/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyPort    int
	chosenPlayer string
	noAutoLaunch bool
)

var playCmd = &cobra.Command{
	Use:   "play <folderName> <fileName>",
	Short: "Stream and play an encrypted video/audio file with instant seeking",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		fileName := args[1]

		cli, err := GetClient()
		if err != nil {
			return err
		}

		fPid, _, flMap, err := cli.GetFiles(folderName)
		if err != nil {
			return err
		}

		actualName, _, _, err := cli.ResolveFile(flMap, fileName)
		if err != nil {
			return err
		}

		streamProxy := proxy.NewStreamProxy(cli, proxyPort)
		streamProxy.UpdateContext(fPid, flMap)

		port, err := streamProxy.Start()
		if err != nil {
			return fmt.Errorf("failed to start stream proxy: %w", err)
		}
		defer streamProxy.Stop()

		streamURL := streamProxy.StreamURL(fPid, actualName)
		fmt.Printf("%s[✓] Stream proxy running on port %d%s\n", ColorGreen, port, ColorReset)
		fmt.Printf("    Streaming URL: %s%s%s\n", ColorCyan, streamURL, ColorReset)

		if noAutoLaunch {
			fmt.Printf("\nOpen the URL above in VLC, MPV, or your web browser.\n")
			fmt.Println("Press Ctrl+C to stop streaming proxy.")
			waitForSignal()
			return nil
		}

		playerBin, playerArgs := findMediaPlayer(chosenPlayer, streamURL)
		if playerBin == "" {
			fmt.Printf("%s[!] No dedicated media player (mpv/vlc/ffplay/iina) found in PATH.%s\n", ColorYellow, ColorReset)
			fmt.Printf("    You can stream this file in any player by opening:\n    %s\n\n", streamURL)
			fmt.Println("Press Ctrl+C to stop streaming proxy.")
			waitForSignal()
			return nil
		}

		fmt.Printf("%s[*] Launching player: %s %v...%s\n", ColorCyan, playerBin, playerArgs, ColorReset)
		playerCmd := exec.Command(playerBin, playerArgs...)
		playerCmd.Stdout = os.Stdout
		playerCmd.Stderr = os.Stderr
		playerCmd.Stdin = os.Stdin

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			<-sigChan
			if playerCmd.Process != nil {
				_ = playerCmd.Process.Kill()
			}
		}()

		if err := playerCmd.Run(); err != nil {

		}

		fmt.Printf("\n%s[✓] Playback ended. Streaming proxy closed.%s\n", ColorGreen, ColorReset)
		return nil
	},
}

var streamCmd = &cobra.Command{
	Use:   "stream <folderName>",
	Short: "Start a local streaming proxy server for all files in a folder",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		folderName := args[0]
		cli, err := GetClient()
		if err != nil {
			return err
		}

		fPid, _, flMap, err := cli.GetFiles(folderName)
		if err != nil {
			return err
		}

		streamProxy := proxy.NewStreamProxy(cli, proxyPort)
		streamProxy.UpdateContext(fPid, flMap)

		port, err := streamProxy.Start()
		if err != nil {
			return fmt.Errorf("failed to start stream proxy: %w", err)
		}
		defer streamProxy.Stop()

		fmt.Printf("\n%s======================================================%s\n", ColorBold+ColorCyan, ColorReset)
		fmt.Printf("%s  MediaHub Real-Time Encrypted Streaming Server%s\n", ColorBold, ColorReset)
		fmt.Printf("  Folder: %s%s%s (PID: %s)\n", ColorGreen, folderName, ColorReset, fPid)
		fmt.Printf("  Proxy Address: %shttp://127.0.0.1:%d%s\n", ColorCyan, port, ColorReset)
		fmt.Printf("%s======================================================%s\n\n", ColorBold+ColorCyan, ColorReset)

		var names []string
		for name := range flMap {
			names = append(names, name)
		}
		sort.Strings(names)

		cols := []TableColumn{
			{Header: "File Name", Align: AlignLeft, Flex: true, MinWidth: 20},
			{Header: "Direct Streaming URL", Align: AlignLeft, MinWidth: 40, TextColor: ColorCyan},
		}
		var rows [][]string
		for _, name := range names {
			url := streamProxy.StreamURL(fPid, name)
			icon := FileTypeIcon(name)
			rows = append(rows, []string{fmt.Sprintf("%s %s", icon, name), url})
		}
		RenderResponsiveTable(cols, rows)

		fmt.Println("\nTo play a stream with mpv or vlc:")
		if len(names) > 0 {
			sampleURL := streamProxy.StreamURL(fPid, names[0])
			fmt.Printf("  mpv \"%s\"\n", sampleURL)
			fmt.Printf("  vlc \"%s\"\n", sampleURL)
		}

		fmt.Printf("\n%sPress Ctrl+C to shutdown stream proxy server.%s\n", ColorYellow, ColorReset)
		waitForSignal()
		return nil
	},
}

func findMediaPlayer(preferred, streamURL string) (string, []string) {
	if preferred != "" {
		if path, err := exec.LookPath(preferred); err == nil {
			return path, []string{streamURL}
		}
	}

	candidates := []string{"mpv", "iina", "vlc", "ffplay"}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, []string{streamURL}
		}
	}

	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/VLC.app"); err == nil {
			return "open", []string{"-a", "VLC", streamURL}
		}
		if _, err := os.Stat("/Applications/IINA.app"); err == nil {
			return "open", []string{"-a", "IINA", streamURL}
		}
		return "open", []string{streamURL}
	}

	if runtime.GOOS == "linux" {
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return path, []string{streamURL}
		}
	}

	return "", nil
}

func waitForSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nStopping streaming proxy...")
}

func init() {
	playCmd.Flags().IntVarP(&proxyPort, "port", "P", 18080, "Port for local decrypted streaming proxy")
	playCmd.Flags().StringVar(&chosenPlayer, "player", "", "Specific player executable to use (mpv, vlc, ffplay, etc.)")
	playCmd.Flags().BoolVar(&noAutoLaunch, "no-player", false, "Do not launch player automatically, only output stream URL")

	streamCmd.Flags().IntVarP(&proxyPort, "port", "P", 18080, "Port for local decrypted streaming proxy")

	RootCmd.AddCommand(playCmd)
	RootCmd.AddCommand(streamCmd)
}
