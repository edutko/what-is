package ssh1

import (
	"bufio"
	"crypto/rsa"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var noPassword = []byte("")
var defaultPassword = loadPassword()

func TestParsePrivateKey(t *testing.T) {
	testCases := []struct {
		name            string
		password        []byte
		expectedKey     rsa.PrivateKey
		expectedComment string
	}{
		{"rsa", noPassword, loadPrivateKeyFromText("rsa.txt"), "SSH1 RSA"},
		{"rsa-encrypted", defaultPassword, loadPrivateKeyFromText("rsa.txt"), "SSH1 RSA (encrypted)"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.name))
			if err != nil {
				t.Fail()
			}

			actualKey, actualComment, err := ParsePrivateKey(data, tc.password)

			assert.Nil(t, err)
			assert.Equal(t, tc.expectedKey, *actualKey)
			assert.Equal(t, tc.expectedComment, actualComment)
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	testCases := []struct {
		name            string
		expectedKey     rsa.PublicKey
		expectedComment string
	}{
		{"rsa.pub", loadPrivateKeyFromText("rsa.txt").PublicKey, "SSH1 RSA"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.name))
			if err != nil {
				t.Fail()
			}

			actualKey, actualComment, err := ParsePublicKey(data)

			assert.Nil(t, err)
			assert.Equal(t, tc.expectedKey, *actualKey)
			assert.Equal(t, tc.expectedComment, actualComment)
		})
	}
}

func loadPrivateKeyFromText(name string) rsa.PrivateKey {
	k := rsa.PrivateKey{}
	k.Primes = make([]*big.Int, 2)

	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		panic(err)
	}
	s := bufio.NewScanner(f)

	for s.Scan() {
		parts := strings.SplitN(s.Text(), "=", 2)
		switch parts[0] {
		case "public_modulus":
			k.N = bigInt(parts[1])
		case "public_exponent":
			k.E = int(bigInt(parts[1]).Int64())
		case "private_exponent":
			k.D = bigInt(parts[1])
		case "private_p":
			k.Primes[0] = bigInt(parts[1])
		case "private_q":
			k.Primes[1] = bigInt(parts[1])
		}
	}

	return k
}

func bigInt(s string) *big.Int {
	i, ok := big.NewInt(0).SetString(s, 0)
	if !ok || i.Cmp(big.NewInt(0)) == 0 {
		panic("invalid big int")
	}
	return i
}

func loadPassword() []byte {
	b, err := os.ReadFile(filepath.Join("testdata", "password"))
	if err != nil {
		panic(err)
	}
	return b
}
