package cryptoconditions

import (
	"bytes"
	"crypto/sha512"

	"errors"

	"golang.org/x/crypto/ed25519"
)

// FfEd25519 implements the Ed25519 fulfillment.
type FfEd25519 struct {
	pubkey    ed25519.PublicKey
	signature []byte
}

// Create a new FfEd25519 fulfillment.
func NewFfEd25519(pubkey ed25519.PublicKey, signature []byte) *FfEd25519 {
	return &FfEd25519{
		pubkey:    pubkey,
		signature: signature,
	}
}

func (ff *FfEd25519) Type() ConditionType {
	return CTEd25519
}

func (ff *FfEd25519) Condition() (*Condition, error) {
	//TODO might need DER encoding
	fingerprint := ff.pubkey
	maxFfLength := uint32(ed25519.PublicKeySize + ed25519.SignatureSize)

	return NewCondition(CTEd25519, FEd25519, fingerprint, maxFfLength), nil
}

func (ff *FfEd25519) Payload() ([]byte, error) {
	buffer := new(bytes.Buffer)

	if err := writeOctetStringOfLength(buffer, ff.pubkey, ed25519.PublicKeySize); err != nil {
		return nil, err
	}
	if err := writeOctetStringOfLength(buffer, ff.signature, ed25519.SignatureSize); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (ff *FfEd25519) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	ff.pubkey, err = readOctetStringOfLength(reader, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	ff.signature, err = readOctetStringOfLength(reader, ed25519.SignatureSize)
	if err != nil {
		return err
	}

	return nil
}

func (ff *FfEd25519) Validate(message []byte) error {
	messageDigest := sha512.Sum512(message)

	if ed25519.Verify(ff.pubkey, messageDigest[:], ff.signature) == true {
		return nil
	} else {
		return errors.New("Unable to Validate Ed25519 fulfillment: signature verification failed.")
	}
}

func (ff *FfEd25519) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
