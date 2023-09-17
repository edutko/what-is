package des

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/des: invalid key size " + strconv.Itoa(int(k))
}

// desCipher is an instance of DES encryption.
type desCipher struct {
	subkeys [16]uint64
}

// A tripleDESCipher is an instance of TripleDES encryption.
type tripleDESCipher struct {
	cipher1, cipher2, cipher3 desCipher
	iv1, iv2, iv3             []byte
}

// NewTripleDESCBCDecrypter creates and returns a new cipher.BlockMode implementing the SSH1
// variation of CBC mode 3DES.
func NewTripleDESCBCDecrypter(key []byte) (cipher.BlockMode, error) {
	if len(key) != 24 {
		return nil, KeySizeError(len(key))
	}

	c := new(tripleDESCipher)
	c.cipher1.generateSubkeys(key[:8])
	c.cipher2.generateSubkeys(key[8:16])
	c.cipher3.generateSubkeys(key[16:])
	c.iv1 = make([]byte, 8)
	c.iv2 = make([]byte, 8)
	c.iv3 = make([]byte, 8)
	return c, nil
}

func (c *tripleDESCipher) BlockSize() int { return BlockSize }

func (c *tripleDESCipher) CryptBlocks(dst, src []byte) {
	if len(src)%c.BlockSize() != 0 {
		panic("src length must be a multiple of the block size")
	}
	if len(dst) < len(src) {
		panic("dst must be at least as large as src")
	}
	for i := 0; i < len(src); i += c.BlockSize() {
		c.decrypt(dst[i:i+c.BlockSize()], src[i:i+c.BlockSize()])
	}
}

func (c *tripleDESCipher) decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/des: output not full block")
	}

	b := binary.BigEndian.Uint64(src)
	b = permuteInitialBlock(b)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	ctLeft, ctRight := left, right
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher3.subkeys[15-2*i], c.cipher3.subkeys[15-(2*i+1)])
	}
	xor(&right, &left, c.iv3)
	c.iv3 = toBytes(ctLeft, ctRight)

	xor(&right, &left, c.iv2)
	for i := 0; i < 8; i++ {
		right, left = feistel(right, left, c.cipher2.subkeys[2*i], c.cipher2.subkeys[2*i+1])
	}
	c.iv2 = toBytes(left, right)

	ctLeft, ctRight = left, right
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher1.subkeys[15-2*i], c.cipher1.subkeys[15-(2*i+1)])
	}
	xor(&right, &left, c.iv1)
	c.iv1 = toBytes(ctLeft, ctRight)

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	preOutput := (uint64(right) << 32) | uint64(left)
	binary.BigEndian.PutUint64(dst, permuteFinalBlock(preOutput))
}

func xor(left, right *uint32, iv []byte) {
	lr := toBytes(*left, *right)
	for i := 0; i < len(lr); i++ {
		lr[i] ^= iv[i]
	}
	*left = binary.BigEndian.Uint32(lr[:4])
	*right = binary.BigEndian.Uint32(lr[4:])
}

func toBytes(left, right uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], left)
	binary.BigEndian.PutUint32(b[4:], right)
	return b
}
