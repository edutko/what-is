package file

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/edutko/what-is/internal/names"
	"github.com/edutko/what-is/internal/util"
)

type JWT struct {
	Header    map[string]any
	Payload   map[string]any
	Signature []byte
}

func ParseJWT(data []byte) (*JWT, error) {
	parts := bytes.Split(data, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 parts, got %d", len(parts))
	}

	jwt := JWT{
		Header:  make(map[string]any),
		Payload: make(map[string]any),
	}

	hdr, err := util.DecodeAnyBase64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("util.DecodeAnyBase64(header): %w", err)
	}
	if err = json.Unmarshal(hdr, &jwt.Header); err != nil {
		return nil, fmt.Errorf("json.Unmarshal(header): %w", err)
	}

	payload, err := util.DecodeAnyBase64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("util.DecodeAnyBase64(payload): %w", err)
	}
	if err = json.Unmarshal(payload, &jwt.Payload); err != nil {
		return nil, fmt.Errorf("json.Unmarshal(header): %w", err)
	}

	jwt.Signature, err = util.DecodeAnyBase64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("util.DecodeAnyBase64(signature): %w", err)
	}

	return &jwt, nil
}

func (j JWT) HeaderAttributes() []Attribute {
	var attrs []Attribute
	for k, v := range j.Header {
		if param, ok := jwtParams[k]; ok {
			if value := param.convert(v); value != "" {
				attrs = append(attrs, Attribute{Name: param.description, Value: value})
			}
		}
	}
	return attrs
}

func (j JWT) PayloadAttributes() []Attribute {
	var attrs []Attribute
	for k, v := range j.Payload {
		if param, ok := jwtParams[k]; ok {
			if value := param.convert(v); value != "" {
				attrs = append(attrs, Attribute{Name: param.description, Value: value})
			}
		}
	}
	return attrs
}

type jwtParam struct {
	description string
	convert     func(any) string
}

var jwtParams = map[string]jwtParam{
	// header
	"alg":      {"Signature Algorithm", sigAlg},
	"typ":      {"Type", str},
	"jku":      {"JWK Set URL", str},
	"jwk":      {"JSON Web Key", str},
	"kid":      {"Key Id", str},
	"x5u":      {"X.509 URL", str},
	"x5c":      {"X.509 Certificate Chain", str},
	"x5t":      {"X.509 Thumbprint (SHA1)", str},
	"x5t#S256": {"X.509 Thumbprint (SHA256)", str},

	// claims
	"aud": {"Audience", str},
	"exp": {"Expiration", unixTime},
	"iat": {"Issued At", unixTime},
	"iss": {"Issuer", str},
	"jti": {"JWT Id", str},
	"nbf": {"Not Before", unixTime},
	"sub": {"Subject", str},
}

func sigAlg(o any) string {
	if s, ok := o.(string); ok {
		switch s {
		case "HS256":
			return names.HMAC + " using " + names.SHA256 + " (HS256)"
		case "HS384":
			return names.HMAC + " using " + names.SHA384 + " (HS384)"
		case "HS512":
			return names.HMAC + " using " + names.SHA512 + " (HS512)"
		case "RS256":
			return names.RSA_PKCS15 + " with " + names.SHA256 + " (RS256)"
		case "RS384":
			return names.RSA_PKCS15 + " with " + names.SHA384 + " (RS384)"
		case "RS512":
			return names.RSA_PKCS15 + " with " + names.SHA512 + " (RS512)"
		case "ES256":
			return names.ECDSA + " using " + names.Secp256r1 + " and " + names.SHA256 + " (ES256)"
		case "ES384":
			return names.ECDSA + " using " + names.Secp384r1 + " and " + names.SHA384 + " (ES384)"
		case "ES512":
			return names.ECDSA + " using " + names.Secp521r1 + " and " + names.SHA512 + " (ES512)"
		case "PS256":
			return names.RSA_PSS + " using " + names.SHA256 + " and " + names.MGF1 + " with " + names.SHA256 + " (PS256)"
		case "PS384":
			return names.RSA_PSS + " using " + names.SHA384 + " and " + names.MGF1 + " with " + names.SHA384 + " (PS384)"
		case "PS512":
			return names.RSA_PSS + " using " + names.SHA512 + " and " + names.MGF1 + " with " + names.SHA512 + " (PS512)"
		default:
			return s
		}
	}
	return ""
}

func str(o any) string {
	if o == nil {
		return ""
	}
	if s, ok := o.(string); ok {
		return s
	}
	return ""
}

func unixTime(o any) string {
	if o == nil {
		return ""
	}
	if s, ok := o.(string); ok {
		if i, err := strconv.Atoi(s); err == nil {
			return time.Unix(int64(i), 0).UTC().Format("2006-01-02 15:04:05")
		}
	}
	return ""
}
