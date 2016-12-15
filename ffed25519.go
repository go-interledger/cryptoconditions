package cryptoconditions

import (
	"fmt"

	"golang.org/x/crypto/ed25519"
)

const ffEd25519EncodedSize = 102

// FfEd25519 implements the Ed25519 fulfillment.
type FfEd25519 struct {
	PublicKey ed25519.PublicKey
	Signature []byte
}

// NewFfEd25519 creates a new FfEd25519 fulfillment.
func NewFfEd25519(pubkey ed25519.PublicKey, signature []byte) *FfEd25519 {
	return &FfEd25519{
		PublicKey: pubkey,
		Signature: signature,
	}
}

func (ff *FfEd25519) ConditionType() ConditionType {
	return CTEd25519
}

func (ff *FfEd25519) Condition() Condition {
	return NewSimpleCondition(ff.ConditionType(), ff.fingerprint(), ff.maxFulfillmentLength())
}

func (ff *FfEd25519) fingerprint() []byte {
	return ff.PublicKey
}

func (ff *FfEd25519) maxFulfillmentLength() int {
	return ffEd25519EncodedSize
}

func (ff *FfEd25519) Validate(condition Condition, message []byte) error {
	if !matches(ff, condition) {
		return fulfillmentDoesNotMatchConditionError
	}

	if ed25519.Verify(ff.PublicKey, message, ff.Signature) {
		return nil
	} else {
		return fmt.Errorf(
			"Unable to Validate Ed25519 fulfillment: signature verification failed for message %x", message)
	}
}

func (ff *FfEd25519) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
