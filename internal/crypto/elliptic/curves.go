package elliptic

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/edutko/what-is/internal/asn1struct"
	"github.com/edutko/what-is/internal/names"
	"github.com/edutko/what-is/internal/oid"
)

func CurveNameFromParameters(p asn1struct.ECParameters) string {
	if p.FieldId.FieldType.Equal(oid.PrimeField) {
		var fieldOrder *big.Int
		if _, err := asn1.Unmarshal(p.FieldId.Parameters.FullBytes, &fieldOrder); err == nil {
			if candidate, ok := namedPrimeCurves[fieldOrder.String()]; ok {
				if primeFieldParamsMatch(candidate, p) {
					return names.Curve(candidate.Name)
				}
			}
		}
	}
	return ""
}

func primeFieldParamsMatch(a primeCurveParameters, b asn1struct.ECParameters) bool {
	if bytes.Equal(a.A, b.Curve.A) && bytes.Equal(a.B, b.Curve.B) && bytes.Equal(a.Seed, b.Curve.Seed.Bytes) &&
		a.Order.Cmp(b.Order) == 0 {
		switch b.Base[0] {
		case 0x00:
			return len(b.Base) == 1 && bytes.Equal(a.BaseX, []byte{0}) && bytes.Equal(a.BaseY, []byte{0})
		case 0x02, 0x03:
			return bytes.Equal(a.BaseX, b.Base[1:])
		case 0x04:
			return bytes.Equal(append(a.BaseX, a.BaseY...), b.Base[1:])
		}
	}
	return false
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
var namedPrimeCurves = map[string]primeCurveParameters{
	"26959946667150639794667015087019630673557916260026308143510066298881": {
		Name:  "P-224",
		Order: mustParseAsBigInt("26959946667150639794667015087019625940457807714424391721682722368061"),
		A:     mustDecodeHex("0xffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe"),
		B:     mustDecodeHex("0xb4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4"),
		BaseX: mustDecodeHex("0xb70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21"),
		BaseY: mustDecodeHex("0xbd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34"),
		Seed:  mustDecodeHex("0xbd713447 99d5c7fc dc45b59f a3b9ab8f 6a948bc5"),
	},
	"115792089210356248762697446949407573530086143415290314195533631308867097853951": {
		Name:  "P-256",
		Order: mustParseAsBigInt("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
		A:     mustDecodeHex("0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc"),
		B:     mustDecodeHex("0x5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b"),
		BaseX: mustDecodeHex("0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296"),
		BaseY: mustDecodeHex("0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5"),
		Seed:  mustDecodeHex("0xc49d3608 86e70493 6a6678e1 139d26b7 819f7e90"),
	},
	"39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319": {
		Name:  "P-384",
		Order: mustParseAsBigInt("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"),
		A:     mustDecodeHex("0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc"),
		B:     mustDecodeHex("0xb3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef"),
		BaseX: mustDecodeHex("0xaa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7"),
		BaseY: mustDecodeHex("0x3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f"),
		Seed:  mustDecodeHex("0xa335926a a319a27a 1d00896a 6773a482 7acdac73"),
	},
	"6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151": {
		Name:  "P-521",
		Order: mustParseAsBigInt("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"),
		A:     mustDecodeHex("0x01ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc"),
		B:     mustDecodeHex("0x0051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00"),
		BaseX: mustDecodeHex("0x00c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66"),
		BaseY: mustDecodeHex("0x0118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650"),
		Seed:  mustDecodeHex("0xd09e8800 291cb853 96cc6717 393284aa a0da64ba"),
	},
}

func mustDecodeHex(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustParseAsBigInt(s string) *big.Int {
	i, ok := big.NewInt(0).SetString(s, 10)
	if !ok {
		panic(fmt.Errorf("failed to parse %s as big int", s))
	}
	return i
}

type primeCurveParameters struct {
	Name  string
	Order *big.Int
	A     asn1struct.FieldElement
	B     asn1struct.FieldElement
	BaseX asn1struct.FieldElement
	BaseY asn1struct.FieldElement
	Seed  []byte
}
