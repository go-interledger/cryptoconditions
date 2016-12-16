package cryptoconditions

import (
	"bytes"
	"crypto/sha256"

	"github.com/pkg/errors"
)

// FfPrefixSha256 implements the PREFIX-SHA-256 fulfillment.
type FfPrefixSha256 struct {
	Prefix []byte

	// Only have either a sub-fulfillment or a sub-condition.
	SubFulfillment Fulfillment `asn1:"choice:fulfillment"`
	subCondition   Condition   `asn1:"-"`
}

// PrefixSha256 creates a new PREFIX-SHA-256 fulfillment.
func PrefixSha256(prefix []byte, subFf Fulfillment) *FfPrefixSha256 {
	return &FfPrefixSha256{
		Prefix:         prefix,
		SubFulfillment: subFf,
	}
}

// PrefixSha256Unfulfilled creates an unfulfilled PREFIX-SHA-256 fulfillment.
func PrefixSha256Unfulfilled(prefix []byte, subCondition Condition) *FfPrefixSha256 {
	return &FfPrefixSha256{
		Prefix:       prefix,
		subCondition: subCondition,
	}
} //TODO consider if we really need this

func (ff *FfPrefixSha256) ConditionType() ConditionType {
	return CTPrefixSha256
}

// SubCondition returns the sub-condition of this fulfillment.
func (ff *FfPrefixSha256) SubCondition() Condition {
	if ff.IsFulfilled() {
		return ff.SubFulfillment.Condition()
	} else {
		return ff.subCondition
	}
}

// IsFulfilled returns true if this fulfillment is fulfilled, i.e. when it contains a sub-fulfillment.
// If false, it only contains a sub-condition.
func (ff *FfPrefixSha256) IsFulfilled() bool {
	return ff.SubFulfillment != nil
}

func (ff *FfPrefixSha256) Condition() Condition {
	return NewCompoundCondition(ff.ConditionType(), ff.fingerprint(), ff.maxFulfillmentLength(), ff.subConditionTypeSet())
}

func (ff *FfPrefixSha256) fingerprint() []byte {
	type fingerprintContent struct {
		prefix       []byte
		subCondition Condition `asn1:"choice:condition"`
	}
	content := fingerprintContent{
		prefix:       ff.Prefix,
		subCondition: ff.SubCondition(),
	}

	encoded, err := Asn1Context.Encode(content)
	if err != nil {
		//TODO
		panic(err)
	}
	hash := sha256.Sum256(encoded)
	return hash[:]
}

func (ff *FfPrefixSha256) maxFulfillmentLength() int {
	encodedPrefix, err := Asn1Context.EncodeWithOptions(ff.Prefix, "tag:0")
	if err != nil {
		//TODO
		panic(err)
	}
	return len(encodedPrefix) + ff.SubCondition().MaxFulfillmentLength()
}

func (ff *FfPrefixSha256) subConditionTypeSet() *ConditionTypeSet {
	set := new(ConditionTypeSet)
	if ff.IsFulfilled() {
		set.addRelevant(ff.SubFulfillment)
	} else {
		set.addRelevant(ff.subCondition)
	}
	return set
}

func (ff *FfPrefixSha256) Validate(condition Condition, message []byte) error {
	if !matches(ff, condition) {
		return fulfillmentDoesNotMatchConditionError
	}

	if !ff.IsFulfilled() {
		return errors.New("Cannot validate unfulfilled fulfillment.")
	}

	buffer := new(bytes.Buffer)
	buffer.Write(ff.Prefix)
	buffer.Write(message)
	newMessage := buffer.Bytes()

	err := ff.SubFulfillment.Validate(nil, newMessage)
	return errors.Wrapf(err, "Failed to validate sub-fulfillment with message %x", newMessage)
}

func (ff *FfPrefixSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
