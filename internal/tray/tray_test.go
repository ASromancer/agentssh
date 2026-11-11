package tray

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestTitle(t *testing.T) {
	if Title(0) != "agentssh" || Title(3) != "agentssh: 3 yêu cầu chờ duyệt" {
		t.Fatalf("%q %q", Title(0), Title(3))
	}
}

func TestIcon(t *testing.T) {
	p := Icon("linux")
	img, err := png.Decode(bytes.NewReader(p))
	if err != nil || img.Bounds().Dx() != 32 || img.Bounds().Dy() != 32 {
		t.Fatalf("png: %v %v", err, img)
	}
	ico := Icon("windows")
	// ICONDIR: reserved 0, type 1, count 1; entry points at the PNG payload.
	if binary.LittleEndian.Uint16(ico[2:]) != 1 || binary.LittleEndian.Uint16(ico[4:]) != 1 {
		t.Fatalf("ico header % x", ico[:6])
	}
	size := binary.LittleEndian.Uint32(ico[14:])
	off := binary.LittleEndian.Uint32(ico[18:])
	if int(off+size) != len(ico) || !bytes.Equal(ico[off:], p) {
		t.Fatal("ico does not wrap the png")
	}
}
