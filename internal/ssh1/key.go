package ssh1

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

const Header = "SSH PRIVATE KEY FILE FORMAT 1.1\n\x00"

var ErrCorrupted = errors.New("invalid private key data or incorrect password")

func ParsePrivateKey(data, password []byte) (*rsa.PrivateKey, string, error) {
	if !bytes.Equal(data[:len(Header)], []byte(Header)) {
		return nil, "", fmt.Errorf("invalid SSH1 private key")
	}

	r := bytes.NewReader(data[len(Header):])

	b := make([]byte, 1)
	_, _ = r.Read(b)
	cipher := cipherType(b[0])
	reserved := make([]byte, 4)
	_, _ = r.Read(reserved)

	pubBits := make([]byte, 4)
	_, _ = r.Read(pubBits)

	n, err := readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	e, err := readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	comment, err := readString(r)
	if err != nil {
		return nil, "", fmt.Errorf("readString: %w", err)
	}

	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
	}

	if cipher == tripleDES {
		ciphertext, _ := io.ReadAll(r)
		plaintext := decrypt(ciphertext, password)
		r = bytes.NewReader(plaintext)
	}

	// in a valid key, the pair of bytes is repeated
	abab := make([]byte, 4)
	_, _ = r.Read(abab)
	if abab[0] != abab[2] || abab[1] != abab[3] {
		return k, comment, ErrCorrupted
	}

	k.D, err = readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	// qInv
	_, err = readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	// q
	k.Primes = make([]*big.Int, 2)
	k.Primes[1], err = readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	// p
	k.Primes[0], err = readMPInt(r)
	if err != nil {
		return nil, "", fmt.Errorf("readMPInt: %w", err)
	}

	return k, comment, nil
}

func ParsePublicKey(data []byte) (*rsa.PublicKey, string, error) {
	tokens := strings.SplitN(string(data), " ", 4)
	if len(tokens) < 3 {
		return nil, "", fmt.Errorf("invalid SSH1 public key")
	}

	e, err := strconv.Atoi(strings.TrimSpace(tokens[1]))
	if err != nil {
		return nil, "", fmt.Errorf("invalid exponent in SSH1 public key")
	}
	n, ok := big.NewInt(0).SetString(strings.TrimSpace(tokens[2]), 10)
	if !ok {
		return nil, "", fmt.Errorf("invalid modulus in SSH1 public key")
	}

	comment := ""
	if len(tokens) > 3 {
		comment = strings.TrimSpace(tokens[3])
	}

	return &rsa.PublicKey{N: n, E: e}, comment, nil
}

type cipherType int

const (
	noEncryption cipherType = 0
	tripleDES    cipherType = 3
)

func readMPInt(r io.Reader) (*big.Int, error) {
	l := make([]byte, 2)
	_, err := r.Read(l)
	if err != nil {
		return nil, err
	}
	b := make([]byte, (binary.BigEndian.Uint16(l)+7)/8)
	_, err = r.Read(b)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(b), nil
}

func readString(r io.Reader) (string, error) {
	l := make([]byte, 4)
	_, err := r.Read(l)
	if err != nil {
		return "", err
	}
	b := make([]byte, binary.BigEndian.Uint32(l))
	_, err = r.Read(b)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
