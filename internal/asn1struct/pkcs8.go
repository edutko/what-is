package asn1struct

type PKCS8PrivateKey struct {
	Version    int
	Algorithm  AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}
