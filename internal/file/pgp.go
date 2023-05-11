package file

import (
	"bytes"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func readArmoredPGPData(b []byte) (*armor.Block, error) {
	r := bytes.NewReader(b)
	return armor.Decode(r)
}

var pubkeyAlgorithmNames = map[packet.PublicKeyAlgorithm]string{
	packet.PubKeyAlgoRSAEncryptOnly: "RSA (encrypt only)",
	packet.PubKeyAlgoRSASignOnly:    "RSA (sign only)",
	packet.PubKeyAlgoRSA:            "RSA",
	packet.PubKeyAlgoElGamal:        "ElGamal",
	packet.PubKeyAlgoDSA:            "DSA",
	packet.PubKeyAlgoECDH:           "ECDH",
	packet.PubKeyAlgoECDSA:          "ECDSA",
}
