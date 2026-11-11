package brand

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestPNGSizes(t *testing.T) {
	for _, n := range []int{16, 32, 48, 64, 128, 256, 512, 1024} {
		img, err := png.Decode(bytes.NewReader(PNG(n)))
		if err != nil || img.Bounds().Dx() != n || img.Bounds().Dy() != n {
			t.Fatalf("size %d: %v", n, err)
		}
	}
	if PNG(20) != nil {
		t.Fatal("unknown size must return nil")
	}
}

func TestICO(t *testing.T) {
	ico := ICO(16, 256)
	le := binary.LittleEndian
	if le.Uint16(ico[0:]) != 0 || le.Uint16(ico[2:]) != 1 || le.Uint16(ico[4:]) != 2 {
		t.Fatalf("header % x", ico[:6])
	}
	for i, n := range []int{16, 256} {
		e := ico[6+16*i:]
		w := int(e[0])
		if w == 0 {
			w = 256
		}
		size, off := le.Uint32(e[8:]), le.Uint32(e[12:])
		if w != n || le.Uint16(e[6:]) != 32 || !bytes.Equal(ico[off:off+size], PNG(n)) {
			t.Fatalf("entry %d wrong", i)
		}
	}
}

func TestICNS(t *testing.T) {
	b := ICNS()
	be := binary.BigEndian
	if string(b[:4]) != "icns" || int(be.Uint32(b[4:])) != len(b) {
		t.Fatalf("header %q %d/%d", b[:4], be.Uint32(b[4:]), len(b))
	}
	want := map[string]int{"icp4": 16, "icp5": 32, "icp6": 64, "ic07": 128, "ic08": 256, "ic09": 512, "ic10": 1024}
	for p := 8; p < len(b); {
		typ, n := string(b[p:p+4]), int(be.Uint32(b[p+4:]))
		size, ok := want[typ]
		if !ok || !bytes.Equal(b[p+8:p+n], PNG(size)) {
			t.Fatalf("entry %s wrong", typ)
		}
		delete(want, typ)
		p += n
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
}
