package cryptoconditions

import (
	"bytes"
	"crypto/sha256"

	"io"

	"github.com/pkg/errors"
)

const (
	ffPrefixSha256Features Features = FSha256 | FPrefix
)

// FfPrefixSha256 implements the Prefix-SHA-256 fulfillment.
type FfPrefixSha256 struct {
	prefix []byte

	// Only have either a sub-fulfillment or a sub-condition.
	subFf   Fulfillment
	subCond *Condition
}

// NewFfPrefixSha256 creates a new FfPrefixSha256 fulfillment.
func NewFfPrefixSha256(prefix []byte, subFf Fulfillment) *FfPrefixSha256 {
	return &FfPrefixSha256{
		prefix: prefix,
		subFf:  subFf,
	}
}

// NewFfPrefixSha256Unfulfilled creates an unfulfilled FfPrefixSha256 fulfillment.
func NewFfPrefixSha256Unfulfilled(prefix []byte, subCondition *Condition) *FfPrefixSha256 {
	return &FfPrefixSha256{
		prefix:  prefix,
		subCond: subCondition,
	}
}

func (ff *FfPrefixSha256) Type() ConditionType {
	return CTPrefixSha256
}

// Prefix returns the prefix used in this fulfillment.
func (ff *FfPrefixSha256) Prefix() []byte {
	return ff.prefix
}

// SubFulfillment returns the sub-fulfillment of this fulfillment when IsFulfilled() is true.
func (ff *FfPrefixSha256) SubFulfillment() Fulfillment {
	return ff.subFf
}

// SubCondition returns the sub-condition of this fulfillment.
func (ff *FfPrefixSha256) SubCondition() (*Condition, error) {
	if ff.IsFulfilled() {
		return ff.subFf.Condition()
	} else {
		return ff.subCond, nil
	}
}

// IfFulfilled returns true if this fulfillment is fulfilled, i.e. when it contains a sub-fulfillment.
// If false, it only contains a sub-condition.
func (ff *FfPrefixSha256) IsFulfilled() bool {
	return ff.subFf != nil
}

func (ff *FfPrefixSha256) Condition() (*Condition, error) {
	subCondition, err := ff.SubCondition()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate sub-condition")
	}
	features := subCondition.Features | ffPrefixSha256Features

	digest := sha256.New()
	if err := ff.writeFingerprintContent(digest); err != nil {
		return nil, errors.Wrap(err, "Failed to write fingerprint content")
	}
	fingerprint := digest.Sum(nil)

	maxFulfillmentLength, err := ff.calculateMaxFulfillmentLength(subCondition)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to calculate max fulfillment length")
	}

	return NewCondition(CTPrefixSha256, features, fingerprint[:], maxFulfillmentLength), nil
}

func (ff *FfPrefixSha256) Payload() ([]byte, error) {
	if !ff.IsFulfilled() {
		return nil, errors.New("Cannot generate payload of unfulfilled fulfillment.")
	}

	buffer := new(bytes.Buffer)
	if err := writeOctetString(buffer, ff.prefix); err != nil {
		return nil, errors.Wrap(err, "Failed to write octet string of prefix")
	}
	if err := SerializeFulfillment(buffer, ff.subFf); err != nil {
		return nil, errors.Wrap(err, "Failed to serialize sub-fulfillment")
	}

	return buffer.Bytes(), nil
}

func (ff *FfPrefixSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	if ff.prefix, err = readOctetString(reader); err != nil {
		return errors.Wrap(err, "Failed to read octet string of prefix")
	}
	if ff.subFf, err = DeserializeFulfillment(reader); err != nil {
		return errors.Wrap(err, "Failed to read octet string of sub-fulfillment")
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

	return errors.Wrapf(ff.subFf.Validate(buffer.Bytes()), "Failed to validate sub-fulfillment with message %x", message)
}

func (ff *FfPrefixSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}

func (ff *FfPrefixSha256) calculateMaxFulfillmentLength(subCondition *Condition) (uint32, error) {
	length := uint32(len(ff.prefix))
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

func (ff *FfPrefixSha256) writeFingerprintContent(w io.Writer) error {
	subCondition, err := ff.SubCondition()
	if err != nil {
		return errors.Wrap(err, "Failed to generate sub-condition")
	}

	if err := writeOctetString(w, ff.prefix); err != nil {
		return errors.Wrap(err, "Failed to write octet string of prefix")
	}
	if err := SerializeCondition(w, subCondition); err != nil {
		return errors.Wrap(err, "Failed to serialize sub-condition")
	}
	return nil
}
