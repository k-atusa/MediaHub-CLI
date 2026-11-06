package client

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	image.RegisterFormat("jpeg", "\xff\xd8", jpeg.Decode, jpeg.DecodeConfig)
	image.RegisterFormat("png", "\x89PNG\r\n\x1a\n", png.Decode, png.DecodeConfig)
	image.RegisterFormat("gif", "GIF", gif.Decode, gif.DecodeConfig)
}

func makeThumbnail(img image.Image) []byte {
	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	if w <= 0 || h <= 0 {
		return nil
	}

	ratio := float64(w) / float64(h)
	var nw, nh int

	if ratio >= 0.6666 && ratio <= 1.5 {
		if w >= h {
			nw = 256
			nh = int(256.0 / ratio)
		} else {
			nh = 256
			nw = int(256.0 * ratio)
		}
	} else {
		nw = 256
		nh = 256
	}
	if nw <= 0 {
		nw = 1
	}
	if nh <= 0 {
		nh = 1
	}

	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		for x := 0; x < nw; x++ {
			srcX := bounds.Min.X + (x * w / nw)
			srcY := bounds.Min.Y + (y * h / nh)
			r, g, b, a := img.At(srcX, srcY).RGBA()
			dst.Set(x, y, color.RGBA{
				R: uint8(r >> 8),
				G: uint8(g >> 8),
				B: uint8(b >> 8),
				A: uint8(a >> 8),
			})
		}
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 70}); err != nil {
		return nil
	}
	return buf.Bytes()
}

func generateImageThumbnail(filePath string) []byte {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif":
	default:
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return nil
	}

	return makeThumbnail(img)
}
