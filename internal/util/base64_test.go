package util

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWhichBase64(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected *base64.Encoding
	}{
		{"empty", "", base64.RawStdEncoding},
		{"raw any", "MA", base64.RawStdEncoding},
		{"raw std", "q/A", base64.RawStdEncoding},
		{"raw only std", "+/+", base64.RawStdEncoding},
		{"raw url", "q_A", base64.RawURLEncoding},
		{"raw only url", "-_-", base64.RawURLEncoding},
		{"padded any", "MA==", base64.StdEncoding},
		{"padded std", "q/A=", base64.StdEncoding},
		{"padded only std", "+/+=", base64.StdEncoding},
		{"padded url", "q_A=", base64.URLEncoding},
		{"padded only url", "-_-=", base64.URLEncoding},
		{"with newlines", "SXQncyBtZSwgaGksIEknbSB0aGUgcHJvYmxlbSwgaXQncyBtZQpBdCB0ZWEgdGlt\r\nZSwgZXZlcnlib2R5IGFncmVlcw==", base64.StdEncoding},

		{"short", "a", nil},
		{"invalid", "!@#$", nil},
		{"invalid raw std", "q/!", nil},
		{"invalid padded std", "q/!=", nil},
		{"invalid raw url", "q_!", nil},
		{"invalid padded url", "q_!=", nil},
		{"bad length raw std", "+", nil},
		{"bad length raw url", "-", nil},
		{"bad length padded std", "+a=", nil},
		{"bad length padded url", "-a=", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, WhichBase64([]byte(tc.value)))
		})
	}
}

func TestDecodeAnyBase64(t *testing.T) {
	type testCase struct {
		name     string
		encoded  []byte
		expected []byte
	}
	testCases := []testCase{
		{"rawAny:YQ", []byte("YQ"), []byte("a")},
		{"padAny:YQ==", []byte("YQ=="), []byte("a")},
		{"anyAny:YWE", []byte("YWE"), []byte("aa")},
		{"padAny:YWE=", []byte("YWE="), []byte("aa")},
		{"anyAny:YWFh", []byte("YWFh"), []byte("aaa")},
		{"rawStd:+///", []byte("+///"), []byte{0xfb, 0xff, 0xff}},
		{"rawUrl:-___", []byte("-___"), []byte{0xfb, 0xff, 0xff}},
		{"rawAny:(b64 with newline)", []byte("dGhpcyBpcyBzb21lIHRleHQgdGhhdCBpcyBsb25nIGVub3VnaCB0byB3cmFwIHRo\nZSBiYXNlNjQ"), []byte("this is some text that is long enough to wrap the base64")},
	}

	encodings := []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding}
	encodingNames := []string{"rawStd", "rawURL", "padStd", "padUrl"}
	for i := 0; i < 25; i++ {
		for j, encoding := range encodings {
			tc := testCase{
				encoded:  make([]byte, encoding.EncodedLen(i)),
				expected: make([]byte, i),
			}
			_, err := rand.Read(tc.expected)
			if err != nil {
				t.Fatal(err)
			}
			encoding.Encode(tc.encoded, tc.expected)
			tc.name = encodingNames[j] + ":" + string(tc.encoded)
			testCases = append(testCases, tc)
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeAnyBase64(tc.encoded)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, decoded)
		})
	}
}

func TestDecodeAnyBase64_err(t *testing.T) {
	testCases := []struct {
		name    string
		encoded string
	}{
		{"short", "a"},
		{"invalid", "!@#$"},
		{"invalid raw std", "q/!"},
		{"invalid padded std", "q/!="},
		{"invalid raw url", "q_!"},
		{"invalid padded url", "q_!="},
		{"bad length raw std", "+"},
		{"bad length raw url", "-"},
		{"bad length padded std", "+a="},
		{"bad length padded url", "-a="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeAnyBase64([]byte(tc.encoded))
			assert.ErrorIs(t, err, ErrInvalidBase64)
			assert.Nil(t, decoded)
		})
	}
}
