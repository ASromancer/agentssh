// Package brand holds the Ostiary logo sources, the rendered PNGs and the
// ICO/ICNS packers used by the tray, the web UI and the installers.
package brand

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
)

//go:embed png/*.png
var pngs embed.FS

//go:embed mark.svg
var MarkSVG []byte

//go:embed app-icon.svg
var AppIconSVG []byte

// PNG returns the app icon rendered at size×size, or nil if that size is not shipped.
func PNG(size int) []byte {
	b, err := pngs.ReadFile(fmt.Sprintf("png/ostiary-%d.png", size))
	if err != nil {
		return nil
	}
	return b
}

// ICO packs the given sizes as PNG payloads (Windows Vista and later).
func ICO(sizes ...int) []byte {
	var hdr, data bytes.Buffer
	le := func(v any) { binary.Write(&hdr, binary.LittleEndian, v) }
	le(uint16(0))
	le(uint16(1))
	le(uint16(len(sizes)))
	off := 6 + 16*len(sizes)
	for _, n := range sizes {
		p := PNG(n)
		dim := byte(n)
		if n >= 256 {
			dim = 0
		}
		hdr.Write([]byte{dim, dim, 0, 0})
		le(uint16(1))
		le(uint16(32))
		le(uint32(len(p)))
		le(uint32(off + data.Len()))
		data.Write(p)
	}
	return append(hdr.Bytes(), data.Bytes()...)
}

// ICNS packs the macOS icon family with PNG payloads.
func ICNS() []byte {
	var body bytes.Buffer
	for _, e := range []struct {
		typ  string
		size int
	}{{"icp4", 16}, {"icp5", 32}, {"icp6", 64}, {"ic07", 128}, {"ic08", 256}, {"ic09", 512}, {"ic10", 1024}} {
		p := PNG(e.size)
		body.WriteString(e.typ)
		binary.Write(&body, binary.BigEndian, uint32(8+len(p)))
		body.Write(p)
	}
	var out bytes.Buffer
	out.WriteString("icns")
	binary.Write(&out, binary.BigEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}
