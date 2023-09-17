package ssh1

import (
	"crypto/md5"

	"github.com/edutko/what-is/internal/ssh1/des"
)

func decrypt(ciphertext, password []byte) []byte {
	h := md5.Sum(password)
	k := append(h[:], h[:8]...)
	c, err := des.NewTripleDESCBCDecrypter(k)
	if err != nil {
		panic(err)
	}

	plaintext := make([]byte, len(ciphertext))
	c.CryptBlocks(plaintext, ciphertext)

	return plaintext
}
