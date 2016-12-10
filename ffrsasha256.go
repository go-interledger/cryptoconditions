package cryptoconditions

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	ffRsaSha256Features Features = FSha256 | FRsaPss

	ffRsaSha256MinimumModulusLength = 128
	ffRsaSha256MaximumModulusLength = 512
	ffRsaSha256PublicExponent       = 65537
)

// FfRsaSha256 implements the RSA-SHA-256 fulfillment.
type FfRsaSha256 struct {
	modulus   *big.Int
	signature []byte
}

// Create a new FfRsaSha256 fulfillment.
func NewFfRsaSha256(modulus *big.Int, signature []byte) (*FfRsaSha256, error) {
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
		modulus:   modulus,
		signature: signature,
	}, nil
}

func (ff *FfRsaSha256) Type() ConditionType {
	return CTRsaSha256
}

func (ff *FfRsaSha256) Modulus() *big.Int {
	return ff.modulus
}

func (ff *FfRsaSha256) Signature() []byte {
	return ff.signature
}

func (ff *FfRsaSha256) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: ff.modulus,
		E: ffRsaSha256PublicExponent,
	}
}

func (ff *FfRsaSha256) Condition() (*Condition, error) {
	fingerprint := sha256.Sum256(ff.modulus.Bytes())
	maxFfLength, err := ff.calculateMaxFulfillmentLength()
	if err != nil {
		return nil, err
	}
	return NewCondition(CTRsaSha256, ffRsaSha256Features, fingerprint[:], maxFfLength), nil
}

func (ff *FfRsaSha256) Payload() ([]byte, error) {
	buffer := new(bytes.Buffer)
	if err := writeOctetString(buffer, ff.modulus.Bytes()); err != nil {
		return nil, err
	}
	if err := writeOctetString(buffer, ff.signature); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (ff *FfRsaSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	modulusBytes, err := readOctetString(reader)
	if err != nil {
		return err
	}
	ff.modulus = new(big.Int).SetBytes(modulusBytes)
	if ff.signature, err = readOctetString(reader); err != nil {
		return err
	}

	return nil
}

func (ff *FfRsaSha256) Validate(message []byte) error {
	return rsa.VerifyPSS(ff.PublicKey(), crypto.SHA256, message, ff.signature, nil)
}

func (ff *FfRsaSha256) String() string {
	uri, _ := Uri(ff)
	return uri
}

func (ff *FfRsaSha256) calculateMaxFulfillmentLength() (uint32, error) {
	payload, err := ff.Payload()
	return uint32(len(payload)), err
}
