package cryptoconditions

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	"io"

	"github.com/pkg/errors"
)

const (
	ffRsaSha256Features Features = FSha256 | FRsaPss

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
	modulus   *big.Int
	signature []byte
}

// NewFfRsaSha256 creates a new FfRsaSha256 fulfillment.
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

// Signature returns the signature provided in this fulfillment.
func (ff *FfRsaSha256) Signature() []byte {
	return ff.signature
}

// PublicKey returns the RSA public key used in this fulfillment.
func (ff *FfRsaSha256) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: ff.modulus,
		E: ffRsaSha256PublicExponent,
	}
}

func (ff *FfRsaSha256) Condition() (*Condition, error) {
	digest := sha256.New()
	if err := writeOctetString(digest, ff.modulus.Bytes()); err != nil {
		return nil, err
	}
	fingerprint := digest.Sum(nil)

	maxFfLength, err := ff.calculateMaxFulfillmentLength()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to calculate max fulfillment length")
	}

	return NewCondition(CTRsaSha256, ffRsaSha256Features, fingerprint[:], maxFfLength), nil
}

func (ff *FfRsaSha256) Payload() ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := ff.writePayload(buffer)
	return buffer.Bytes(), err
}

// writePayload writes the payload to the writer
func (ff *FfRsaSha256) writePayload(w io.Writer) error {
	if err := writeOctetString(w, ff.modulus.Bytes()); err != nil {
		return errors.Wrap(err, "Failed to write octet string of modulus")
	}
	if err := writeOctetString(w, ff.signature); err != nil {
		return errors.Wrap(err, "Failed to write octet string of signature")
	}
	return nil
}

func (ff *FfRsaSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	modulusBytes, err := readOctetString(reader)
	if err != nil {
		return errors.Wrap(err, "Failed to read octet string of modulus")
	}
	ff.modulus = new(big.Int).SetBytes(modulusBytes)
	if ff.signature, err = readOctetString(reader); err != nil {
		return errors.Wrap(err, "Failed to read octet string of signature")
	}

	return nil
}

func (ff *FfRsaSha256) Validate(message []byte) error {
	err := rsa.VerifyPSS(ff.PublicKey(), crypto.SHA256, message, ff.signature, &ffRsaSha256PssOpts)
	return errors.Wrapf(err, "Failed to verify RSA signature of message %x", message)
}

func (ff *FfRsaSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}

func (ff *FfRsaSha256) calculateMaxFulfillmentLength() (uint32, error) {
	counter := new(writeCounter)
	err := ff.writePayload(counter)
	return uint32(counter.Counter()), errors.Wrap(err, "Failed to write payload")
}
