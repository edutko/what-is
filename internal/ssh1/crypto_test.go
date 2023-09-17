package ssh1

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_decrypt(t *testing.T) {
	expectedPlaintext := readPrivateSectionOfKey("rsa")
	ciphertext := readPrivateSectionOfKey("rsa-encrypted")
	password := loadPassword()

	actualPlaintext := decrypt(ciphertext, password)

	assert.Equal(t, expectedPlaintext[4:], actualPlaintext[4:])
}

func readPrivateSectionOfKey(name string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		panic(err)
	}

	// cipher type, reserved bytes,public key size (bits)
	skip := len(Header) + 1 + 4 + 4
	r := bytes.NewReader(data[skip:])
	_, _ = readMPInt(r)  // N
	_, _ = readMPInt(r)  // E
	_, _ = readString(r) // comment

	data, _ = io.ReadAll(r)
	return data
}
