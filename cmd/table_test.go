package cmd

import (
	"testing"
)

func TestRenderTable(t *testing.T) {
	cols := []TableColumn{
		{Header: "File Name", Align: AlignLeft, Flex: true, MinWidth: 24},
		{Header: "Size", Align: AlignRight, MinWidth: 10, TextColor: ColorYellow},
		{Header: "File PID", Align: AlignLeft, MinWidth: 24, MaxWidth: 24, TextColor: ColorGray},
	}
	rows := [][]string{
		{FileTypeIcon("1681697997.jpg") + " 1681697997.jpg", FormatBytes(37770), "91d28d9b163b76bf059b3460"},
		{FileTypeIcon("Med_Sci_Law.pdf") + " Med_Sci_Law.pdf", FormatBytes(221630), "cc27fc5a90c001a5ec045e79"},
		{FileTypeIcon("인데아멍.mp4") + " 인데아멍.mp4", FormatBytes(29340000), "ef27108c8999637f0cfb298f"},
		{FileTypeIcon("조용훈 추락 이후.mp4") + " 조용훈 추락 이후.mp4", FormatBytes(8340000), "7128bf7997e08db856eb7150"},
		{FileTypeIcon("호남반도체 시비거는 미7공군 대학생 항의방문.mp4") + " 호남반도체 시비거는 미7공군 대학생 항의방문.mp4", FormatBytes(14840000), "70dccf1949327a3487e3788f"},
	}
	RenderResponsiveTable(cols, rows)
}
