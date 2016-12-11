package cryptoconditions

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

const (
	ffPrefixSha256Features Features = FSha256 | FPrefix
)

// FfPrefixSha256 implements the Prefix-SHA-256 fulfillment.
type FfPrefixSha256 struct {
	prefix []byte

	// Only have either a subfulfillment or a subcondition.
	subFf   Fulfillment
	subCond *Condition
}

// Create a new FfPrefixSha256 fulfillment.
func NewFfPrefixSha256(prefix []byte, subFf Fulfillment) *FfPrefixSha256 {
	return &FfPrefixSha256{
		prefix: prefix,
		subFf:  subFf,
	}
}

// Create an unfulfilled FfPrefixSha256 fulfillment.
func NewFfPrefixSha256Unfulfilled(prefix []byte, subCondition *Condition) *FfPrefixSha256 {
	return &FfPrefixSha256{
		prefix:  prefix,
		subCond: subCondition,
	}
}

func (ff *FfPrefixSha256) Type() ConditionType {
	return CTPrefixSha256
}

func (ff *FfPrefixSha256) Prefix() []byte {
	return ff.prefix
}

// IfFulfilled returns true if this fulfillment is fulfilled, i.e. when it contains a subfilfullment.
// If false, it only contains a subcondition.
func (ff *FfPrefixSha256) IsFulfilled() bool {
	return ff.subFf != nil
}

func (ff *FfPrefixSha256) Condition() (*Condition, error) {
	var subCondition *Condition
	var err error
	if ff.IsFulfilled() {
		subCondition, err = ff.subFf.Condition()
		if err != nil {
			return nil, err
		}
	} else {
		subCondition = ff.subCond
	}

	features := subCondition.Features | ffPrefixSha256Features

	fc, err := ff.calculateFingerprintContent(ff.prefix, subCondition)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(fc)

	maxFulfillmentLength, err := ff.calculateMaxFulfillmentLength(ff.prefix, subCondition)
	if err != nil {
		return nil, err
	}

	return NewCondition(CTPrefixSha256, features, fingerprint[:], maxFulfillmentLength), nil
}

func (ff *FfPrefixSha256) Payload() ([]byte, error) {
	if !ff.IsFulfilled() {
		return nil, errors.New("Cannot generate payload of unfulfilled fulfillment.")
	}

	buffer := new(bytes.Buffer)
	if err := writeOctetString(buffer, ff.prefix); err != nil {
		return nil, err
	}
	if err := SerializeFulfillment(buffer, ff.subFf); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (ff *FfPrefixSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	if ff.prefix, err = readOctetString(reader); err != nil {
		return err
	}
	if ff.subFf, err = DeserializeFulfillment(reader); err != nil {
		return err
	}

	return nil
}

func (ff *FfPrefixSha256) Validate(message []byte) error {
	if !ff.IsFulfilled() {
		return errors.New("Cannot validate unfulfilled fulfillment.")
	}

	buffer := new(bytes.Buffer)
	buffer.Write(ff.prefix)
	buffer.Write(message)

	return ff.subFf.Validate(buffer.Bytes())
}

func (ff *FfPrefixSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}

func (ff *FfPrefixSha256) calculateMaxFulfillmentLength(prefix []byte, subCondition *Condition) (uint32, error) {
	length := uint32(len(prefix))
	if length < 128 {
		length = length + 1
	} else if length <= 255 {
		length = length + 2
	} else if length <= 65535 {
		length = length + 3
	} else if length <= 16777215 {
		length = length + 4
	} else {
		return 0, errors.New("Field lengths of greater than 16777215 are not supported.")
	}
	length = length + subCondition.MaxFulfillmentLength

	return length, nil
}

func (ff *FfPrefixSha256) calculateFingerprintContent(prefix []byte, subCondition *Condition) ([]byte, error) {
	buffer := new(bytes.Buffer)

	if err := writeOctetString(buffer, prefix); err != nil {
		return nil, err
	}
	if err := SerializeCondition(buffer, subCondition); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
