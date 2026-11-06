package cmd

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorGray    = "\033[90m"
)

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func ReadPasswordSecurely(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func RenderProgressBar(label string, current, total int64, speed float64) {
	if total <= 0 {
		return
	}
	width := 30
	percent := float64(current) / float64(total)
	if percent > 1.0 {
		percent = 1.0
	}
	filled := int(percent * float64(width))

	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">" + strings.Repeat(" ", width-filled-1)
	}

	speedStr := ""
	if speed > 0 {
		speedStr = fmt.Sprintf(" %s/s", FormatBytes(int64(speed)))
	}

	fmt.Printf("\r%s [%s] %s / %s (%.1f%%)%s",
		label,
		bar,
		FormatBytes(current),
		FormatBytes(total),
		percent*100.0,
		speedStr,
	)

	if current >= total {
		fmt.Println()
	}
}

func PrintTable(headers []string, rows [][]string) {
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	fmt.Print(ColorBold + ColorCyan)
	for i, h := range headers {
		fmt.Printf("%-*s  ", colWidths[i], h)
	}
	fmt.Println(ColorReset)

	for i := range headers {
		fmt.Print(strings.Repeat("-", colWidths[i]) + "  ")
	}
	fmt.Println()

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				fmt.Printf("%-*s  ", colWidths[i], cell)
			}
		}
		fmt.Println()
	}
}
