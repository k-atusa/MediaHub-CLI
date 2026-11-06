package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorGray    = "\033[90m"
)

type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
)

type TableColumn struct {
	Header    string
	Align     Alignment
	MinWidth  int
	MaxWidth  int
	Flex      bool
	TextColor string
}

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

func FileTypeIcon(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".mp4", ".mkv", ".webm", ".mov", ".avi", ".ts", ".flv":
		return "🎬"
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg":
		return "🖼️"
	case ".pdf", ".epub":
		return "📕"
	case ".txt", ".md", ".json", ".log", ".yaml", ".yml", ".py", ".go", ".c", ".cpp":
		return "📄"
	case ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a":
		return "🎵"
	case ".apk", ".zip", ".tar", ".gz", ".7z", ".rar":
		return "📦"
	default:
		return "📎"
	}
}

func padString(s string, targetWidth int, align Alignment) string {
	curWidth := runewidth.StringWidth(s)
	if curWidth >= targetWidth {
		return s
	}
	pad := strings.Repeat(" ", targetWidth-curWidth)
	if align == AlignRight {
		return pad + s
	}
	return s + pad
}

func truncateString(s string, maxWidth int) string {
	if maxWidth <= 3 {
		return runewidth.Truncate(s, maxWidth, "")
	}
	if runewidth.StringWidth(s) <= maxWidth {
		return s
	}
	return runewidth.Truncate(s, maxWidth, "...")
}

func RenderResponsiveTable(cols []TableColumn, rows [][]string) {
	if len(cols) == 0 || len(rows) == 0 {
		return
	}

	termWidth := 100
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 40 {
		termWidth = w
	}

	numCols := len(cols)
	widths := make([]int, numCols)
	for i, col := range cols {
		widths[i] = runewidth.StringWidth(col.Header)
		if col.MinWidth > widths[i] {
			widths[i] = col.MinWidth
		}
	}

	for _, row := range rows {
		for i := 0; i < numCols && i < len(row); i++ {
			w := runewidth.StringWidth(row[i])
			if w > widths[i] {
				widths[i] = w
			}
		}
	}

	colSpacing := 3
	fixedTotal := (numCols - 1) * colSpacing
	flexIdx := -1
	for i, col := range cols {
		if col.Flex {
			flexIdx = i
		} else {
			if col.MaxWidth > 0 && widths[i] > col.MaxWidth {
				widths[i] = col.MaxWidth
			}
			fixedTotal += widths[i]
		}
	}

	if flexIdx != -1 {
		availableForFlex := termWidth - fixedTotal
		if availableForFlex < cols[flexIdx].MinWidth {
			availableForFlex = cols[flexIdx].MinWidth
		}
		if availableForFlex < 15 {
			availableForFlex = 15
		}
		widths[flexIdx] = availableForFlex
	}

	headerLine := ""
	for i, col := range cols {
		hText := truncateString(col.Header, widths[i])
		headerLine += padString(hText, widths[i], col.Align)
		if i < numCols-1 {
			headerLine += strings.Repeat(" ", colSpacing)
		}
	}
	fmt.Println(ColorBold + ColorCyan + headerLine + ColorReset)

	sepLine := ""
	for i := range cols {
		sepLine += strings.Repeat("─", widths[i])
		if i < numCols-1 {
			sepLine += strings.Repeat(" ", colSpacing)
		}
	}
	fmt.Println(ColorDim + ColorGray + sepLine + ColorReset)

	for _, row := range rows {
		rowLine := ""
		for i := 0; i < numCols && i < len(row); i++ {
			cell := truncateString(row[i], widths[i])
			padded := padString(cell, widths[i], cols[i].Align)
			if cols[i].TextColor != "" {
				rowLine += cols[i].TextColor + padded + ColorReset
			} else {
				rowLine += padded
			}
			if i < numCols-1 {
				rowLine += strings.Repeat(" ", colSpacing)
			}
		}
		fmt.Println(rowLine)
	}
}

func PrintTable(headers []string, rows [][]string) {
	cols := make([]TableColumn, len(headers))
	for i, h := range headers {
		cols[i] = TableColumn{
			Header: h,
			Align:  AlignLeft,
		}
		if i == 0 {
			cols[i].Flex = true
		}
	}
	RenderResponsiveTable(cols, rows)
}
