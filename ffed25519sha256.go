package cryptoconditions

import (
	"fmt"

	"crypto/sha256"

	"golang.org/x/crypto/ed25519"
)

const ffEd25519Sha256EncodedSize = 102

// FfEd25519Sha256 implements the ED25519-SHA-256 fulfillment.
type FfEd25519Sha256 struct {
	PublicKey ed25519.PublicKey
	Signature []byte
}

// NewEd25519Sha256 creates a new ED25519-SHA-256 fulfillment.
func NewEd25519Sha256(pubkey ed25519.PublicKey, signature []byte) *FfEd25519Sha256 {
	return &FfEd25519Sha256{
		PublicKey: pubkey,
		Signature: signature,
	}
}

func (ff *FfEd25519Sha256) ConditionType() ConditionType {
	return CTEd25519Sha256
}

func (ff *FfEd25519Sha256) Condition() Condition {
	return NewSimpleCondition(ff.ConditionType(), ff.fingerprint(), ff.maxFulfillmentLength())
}

func (ff *FfEd25519Sha256) fingerprint() []byte {
	hash := sha256.Sum256(ff.PublicKey)
	return hash[:]
}

func (ff *FfEd25519Sha256) maxFulfillmentLength() int {
	return ffEd25519Sha256EncodedSize
}

func (ff *FfEd25519Sha256) Validate(condition Condition, message []byte) error {
	if !matches(ff, condition) {
		return fulfillmentDoesNotMatchConditionError
	}

	if ed25519.Verify(ff.PublicKey, message, ff.Signature) {
		return nil
	} else {
		return fmt.Errorf(
			"Unable to Validate Ed25519Sha256 fulfillment: signature verification failed for message %x", message)
	}
}

func (ff *FfEd25519Sha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
