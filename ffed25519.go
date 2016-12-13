package cryptoconditions

import (
	"bytes"

	"github.com/pkg/errors"

	"fmt"

	"golang.org/x/crypto/ed25519"
)

// FfEd25519 implements the Ed25519 fulfillment.
type FfEd25519 struct {
	pubkey    ed25519.PublicKey
	signature []byte
}

// NewFfEd25519 creates a new FfEd25519 fulfillment.
func NewFfEd25519(pubkey ed25519.PublicKey, signature []byte) *FfEd25519 {
	return &FfEd25519{
		pubkey:    pubkey,
		signature: signature,
	}
}

func (ff *FfEd25519) Type() ConditionType {
	return CTEd25519
}

// PublicKey returns the public key used in the fulfillment.
func (ff *FfEd25519) PublicKey() ed25519.PublicKey {
	return ff.pubkey
}

// Signature returns the signature provided in this fulfillment.
func (ff *FfEd25519) Signature() []byte {
	return ff.signature
}

func (ff *FfEd25519) Condition() (*Condition, error) {
	//TODO might need DER encoding
	fingerprint := ff.pubkey
	maxFfLength := uint32(ed25519.PublicKeySize + ed25519.SignatureSize)

	return NewCondition(CTEd25519, FEd25519, fingerprint, maxFfLength), nil
}

func (ff *FfEd25519) Payload() ([]byte, error) {
	buffer := new(bytes.Buffer)

	if err := writeByteArray(buffer, ff.pubkey); err != nil {
		return nil, errors.Wrap(err, "Failed to write octet string of pubkey")
	}
	if err := writeByteArray(buffer, ff.signature); err != nil {
		return nil, errors.Wrap(err, "Failed to write octet string of signature")
	}

	return buffer.Bytes(), nil
}

func (ff *FfEd25519) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	ff.pubkey, err = readByteArray(reader, ed25519.PublicKeySize)
	if err != nil {
		return errors.Wrap(err, "Failed to read octet string of pubkey")
	}
	ff.signature, err = readByteArray(reader, ed25519.SignatureSize)
	if err != nil {
		return errors.Wrap(err, "Failed to read octet string of pubkey")
	}

	return nil
}

func (ff *FfEd25519) Validate(message []byte) error {
	if ed25519.Verify(ff.pubkey, message, ff.signature) {
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
