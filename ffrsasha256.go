package cryptoconditions

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	"github.com/pkg/errors"
)

const (
	// The RSA parameters we have to use.
	ffRsaSha256MinimumModulusLength = 128
	ffRsaSha256MaximumModulusLength = 512
	ffRsaSha256PublicExponent       = 65537
)

var ffRsaSha256PssOpts rsa.PSSOptions = rsa.PSSOptions{
	SaltLength: 32,
	Hash:       crypto.SHA256,
}

// FfRsaSha256 implements the RSA-SHA-256 fulfillment.
type FfRsaSha256 struct {
	PublicKey *rsa.PublicKey
	Signature []byte
}

// RsaSha256 creates a new RSA-SHA-256 fulfillment.
func RsaSha256(modulus *big.Int, signature []byte) (*FfRsaSha256, error) {
	// sanity check the modulus
	modulusLength := len(modulus.Bytes())
	if modulusLength < ffRsaSha256MinimumModulusLength {
		return nil, errors.New("Modulus is too small.")
	}
	if modulusLength > ffRsaSha256MaximumModulusLength {
		return nil, errors.New("Modulus is too large.")
	}
	//TODO are these required? present in Java, not in JS
	if modulusLength != len(signature) {
		return nil, errors.New("Modulus and signature must be of the same size.")
	}
	if modulus.Cmp(new(big.Int).SetBytes(signature)) < 0 {
		return nil, errors.New("Modulus must be larger, numerically, than signature.")
	}

	return &FfRsaSha256{
		PublicKey: &rsa.PublicKey{
			N: modulus,
			E: ffRsaSha256PublicExponent,
		},
		Signature: signature,
	}, nil
}

func (ff *FfRsaSha256) ConditionType() ConditionType {
	return CTRsaSha256
}

func (ff *FfRsaSha256) Condition() Condition {
	return NewSimpleCondition(ff.ConditionType(), ff.fingerprint(), ff.maxFulfillmentLength())
}

func (ff *FfRsaSha256) fingerprint() []byte {
	// Fingerprint content is equal to the RSA public key
	encoded, err := Asn1Context.Encode(ff.PublicKey)
	if err != nil {
		//TODO
		panic(err)
	}
	hash := sha256.Sum256(encoded)
	return hash[:]
}

func (ff *FfRsaSha256) maxFulfillmentLength() int {
	//TODO VERIFY
	// Fingerprint content is equal to the RSA public key
	encoded, err := Asn1Context.Encode(ff.PublicKey)
	if err != nil {
		//TODO
		panic(err)
	}
	return 2 * len(encoded)
}

func (ff *FfRsaSha256) Validate(condition Condition, message []byte) error {
	if !matches(ff, condition) {
		return fulfillmentDoesNotMatchConditionError
	}

	err := rsa.VerifyPSS(ff.PublicKey, crypto.SHA256, message, ff.Signature, &ffRsaSha256PssOpts)
	return errors.Wrapf(err, "Failed to verify RSA signature of message %x", message)
}

func (ff *FfRsaSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
