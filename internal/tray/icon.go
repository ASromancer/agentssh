package tray

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

// Title is the tooltip, with the number of requests waiting.
func Title(n int) string {
	if n == 0 {
		return "agentssh"
	}
	return fmt.Sprintf("agentssh: %d yêu cầu chờ duyệt", n)
}

// Icon returns the tray icon: PNG, wrapped as ICO on Windows. It is drawn
// in code (a rounded blue square with a ">_" prompt), so there is no asset.
func Icon(goos string) []byte {
	const n = 32
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	bg := color.NRGBA{0x1f, 0x5f, 0xbf, 0xff}
	fg := color.NRGBA{0xff, 0xff, 0xff, 0xff}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := min(x, n-1-x), min(y, n-1-y) // rounded corners, radius 6
			if dx < 6 && dy < 6 && (6-dx)*(6-dx)+(6-dy)*(6-dy) > 36 {
				continue
			}
			img.Set(x, y, bg)
		}
	}
	for i := 0; i < 8; i++ { // ">"
		for w := 0; w < 3; w++ {
			img.Set(8+i+w, 8+i, fg)
			img.Set(8+i+w, 23-i, fg)
		}
	}
	for x := 17; x < 25; x++ { // "_"
		for w := 0; w < 3; w++ {
			img.Set(x, 21+w, fg)
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	if goos != "windows" {
		return b.Bytes()
	}
	return icoWrap(b.Bytes(), n)
}

// icoWrap packs a PNG into a single-image ICO (Vista+ accepts PNG payloads).
func icoWrap(p []byte, size int) []byte {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	le(uint16(0)) // reserved
	le(uint16(1)) // type: icon
	le(uint16(1)) // count
	b.WriteByte(byte(size))
	b.WriteByte(byte(size))
	b.WriteByte(0) // palette
	b.WriteByte(0) // reserved
	le(uint16(1))  // planes
	le(uint16(32)) // bpp
	le(uint32(len(p)))
	le(uint32(6 + 16)) // offset
	b.Write(p)
	return b.Bytes()
}
