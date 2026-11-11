package tray

import (
	"fmt"

	"github.com/ASromancer/ostiary/internal/brand"
)

// Title is the tooltip, with the number of requests waiting.
func Title(n int) string {
	if n == 0 {
		return "Ostiary"
	}
	return fmt.Sprintf("Ostiary: %d yêu cầu chờ duyệt", n)
}

// Icon returns the tray icon: the brand PNG, or an ICO on Windows.
func Icon(goos string) []byte {
	if goos == "windows" {
		return brand.ICO(16, 32)
	}
	return brand.PNG(32)
}
