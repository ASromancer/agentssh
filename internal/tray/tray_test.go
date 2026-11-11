package tray

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"

	"github.com/ASromancer/ostiary/internal/brand"
)

func TestTitle(t *testing.T) {
	if Title(0) != "Ostiary" || Title(3) != "Ostiary: 3 yêu cầu chờ duyệt" {
		t.Fatalf("%q %q", Title(0), Title(3))
	}
}

func TestIcon(t *testing.T) {
	p := Icon("linux")
	img, err := png.Decode(bytes.NewReader(p))
	if err != nil || img.Bounds().Dx() != 32 || img.Bounds().Dy() != 32 || !bytes.Equal(p, brand.PNG(32)) {
		t.Fatalf("png: %v %v", err, img)
	}
	ico := Icon("windows")
	if !bytes.Equal(ico, brand.ICO(16, 32)) || binary.LittleEndian.Uint16(ico[2:]) != 1 || binary.LittleEndian.Uint16(ico[4:]) != 2 {
		t.Fatalf("ico header % x", ico[:6])
	}
}
