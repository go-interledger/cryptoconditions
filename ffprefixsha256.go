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

	subFf Fulfillment
}

// Create a new FfPrefixSha256 fulfillment.
func NewFfPrefixSha256(prefix []byte, subFf Fulfillment) *FfPrefixSha256 {
	return &FfPrefixSha256{
		prefix: prefix,
		subFf:  subFf,
	}
}

func (ff *FfPrefixSha256) Type() ConditionType {
	return CTPrefixSha256
}

func (ff *FfPrefixSha256) Prefix() []byte {
	return ff.prefix
}

func (ff *FfPrefixSha256) Condition() (*Condition, error) {
	subCondition, err := ff.subFf.Condition()
	if err != nil {
		return nil, err
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
	buffer := new(bytes.Buffer)

	buffer.Write(ff.prefix)
	buffer.Write(message)

	return ff.subFf.Validate(buffer.Bytes())
}

func (ff *FfPrefixSha256) String() string {
	uri, _ := Uri(ff)
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
