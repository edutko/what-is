package util

import (
	"encoding/base64"
	"errors"
)

var ErrInvalidBase64 = errors.New("invalid base64")

func WhichBase64(data []byte) *base64.Encoding {
	var b int
	dataLen := 0
	for _, c := range data {
		w := whichB64[c]
		if w == x {
			return nil
		}
		if w != 0 {
			dataLen++
		}
		b |= w
	}

	if b&b64Pad == b64Pad && dataLen%4 != 0 {
		return nil
	}

	if b&b64Pad == 0 && dataLen%4 == 1 {
		return nil
	}

	switch b {
	case b64Empty, b64Any, b64Std, b64Any | b64Std:
		return base64.RawStdEncoding
	case b64URL, b64Any | b64URL:
		return base64.RawURLEncoding
	case b64Any | b64Pad, b64Std | b64Pad, b64Any | b64Std | b64Pad:
		return base64.StdEncoding
	case b64URL | b64Pad, b64Any | b64URL | b64Pad:
		return base64.URLEncoding
	default:
		return nil
	}
}

func DecodeAnyBase64(b []byte) ([]byte, error) {
	d := WhichBase64(b)
	if d == nil {
		return nil, ErrInvalidBase64
	}

	decoded := make([]byte, d.DecodedLen(len(b)))
	n, err := d.Decode(decoded, b)
	if err != nil {
		// unreachable unless there is a bug in WhichBase
		panic(err)
	}

	return decoded[:n], nil
}

const (
	b64Empty = 0
	b64Any   = 1
	b64Std   = 2
	b64URL   = 4
	b64Pad   = 8
	x        = 255
)

var (
	whichB64 = []int{
		x, x, x, x, x, x, x, x, x, x, 0, x, x, 0, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, 2, x, 4, x, 2,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, x, x, x, 8, x, x,
		x, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, x, x, x, x, 4,
		x, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
		x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
	}
)
