package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFiletype_MatchesName(t *testing.T) {
	testCases := []struct {
		patterns []string
		name     string
		matches  bool
	}{
		{[]string{""}, "a", false},
		{[]string{"a"}, "b", false},
		{[]string{"abc.key1"}, "abc.key", false},
		{[]string{"😎.pem"}, "abc.key", false},

		{[]string{""}, "", false},
		{[]string{"a"}, "a", true},
		{[]string{"abc.key"}, "abc.key", true},
		{[]string{"😎.pem"}, "😎.pem", true},

		{[]string{"*"}, "", false},
		{[]string{"*"}, "a", true},
		{[]string{"*"}, "abc.key", true},
		{[]string{"*"}, "😎.pem", true},

		{[]string{"*.pem"}, "", false},
		{[]string{"*.pem"}, "a", false},
		{[]string{"*.pem"}, "abc.key", false},
		{[]string{"*.pem"}, "😎.pem", true},

		{[]string{"a*"}, "", false},
		{[]string{"a*"}, "a", true},
		{[]string{"a*"}, "abc.key", true},
		{[]string{"a*"}, "😎.pem", false},

		{[]string{"*bc*"}, "", false},
		{[]string{"*bc*"}, "a", false},
		{[]string{"*bc*"}, "abc.key", true},
		{[]string{"*bc*"}, "😎.pem", false},

		{nil, "", false},
		{nil, "a", false},
		{nil, "abc.key", false},
		{nil, "😎.pem", false},
	}

	for _, tc := range testCases {
		ft := filetype{patterns: tc.patterns}
		assert.Equal(t, tc.matches, ft.MatchesName(tc.name))
	}
}

func TestFiletype_MatchesMagic(t *testing.T) {
	testCases := []struct {
		magics  []string
		data    []byte
		matches bool
	}{
		{nil, []byte{}, false},
		{[]string{""}, []byte{}, true},
		{[]string{""}, []byte{0x00, 0x01}, true},
		{[]string{"\x01\x02\x03"}, []byte{0x01, 0x02}, false},

		{[]string{"\xfe\xed\xfe\xed"}, fileContents("java/keystore.jks"), true},
		{[]string{"\xfe\xed\xfa\xce"}, fileContents("java/keystore.jks"), false},
	}

	for _, tc := range testCases {
		ft := filetype{magics: tc.magics}
		assert.Equal(t, tc.matches, ft.MatchesMagic(tc.data))
	}
}

func TestFiletype_SmellsLike(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		identify Identifier
		matches  bool
	}{
		{"empty", []byte{}, IsASN1, false},
		{"junk", []byte{0x01, 0x02}, IsASN1, false},
		{"prime256v1.pub", fileContents("x509/der/prime256v1.pub"), IsASN1, true},
		{"prime256v1-b64", fileContents("asn1/prime256v1-b64std"), IsBase64ASN1, true},
		{"prime256v1-b64url", fileContents("asn1/prime256v1-b64url"), IsBase64ASN1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ft := filetype{identify: tc.identify}
			assert.Equal(t, tc.matches, ft.SmellsLike(tc.name, tc.data, int64(len(tc.data))))
		})
	}
}

func fileContents(name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		panic(err)
	}
	return b
}
