package cryptoconditions

import (
	"bytes"
	"encoding/asn1"
	"reflect"
)

// ConditionType represent one of the predefined condition types in the specification.
type ConditionType int

const (
	CTPreimageSha256 ConditionType = iota

	CTPrefixSha256

	CTThresholdSha256

	CTRsaSha256

	CTEd25519

	// nbKnownConditionTypes is the number of known condition types. Assuming all code up till this number are known,
	// comparing a code with nbKnownConditionTypes determines whether the code is known or not.
	// This number should always be equal to `len(conditionTypeMap)` and `len(fulfillmentTypeMap)`.
	nbKnownConditionTypes
)

// Define these two types so that we don't have to call reflect.TypeOf for every type.
var simpleConditionType, compoundConditionType = reflect.TypeOf(simpleCondition{}), reflect.TypeOf(compoundCondition{})

// conditionTypeMap is a map that maps every ConditionType to either
// the Go type for simpleCondition or compoundCondition.
var conditionTypeMap = map[ConditionType]reflect.Type{
	CTEd25519:         simpleConditionType,
	CTPrefixSha256:    compoundConditionType,
	CTPreimageSha256:  simpleConditionType,
	CTThresholdSha256: compoundConditionType,
	CTRsaSha256:       simpleConditionType,
}

// ConditionTypeSet represents a set of ConditionTypes.
// It is represented as an ASN.1 BIT STRING like defined in the specification.
type ConditionTypeSet asn1.BitString

// Has determines if the given condition type is present.
func (c ConditionTypeSet) Has(conditionType ConditionType) bool {
	return asn1.BitString(c).At(int(conditionType)) == 1
}

// Equals returns true if `other` represents the same condition type set as this. False otherwise.
func (c *ConditionTypeSet) Equals(other *ConditionTypeSet) bool {
	return bytes.Equal(c.Bytes, other.Bytes) && c.BitLength == other.BitLength
}

// Add adds the given condition type to the set.
func (c *ConditionTypeSet) Add(conditionType ConditionType) {
	newBitLength := max(c.BitLength, int(conditionType))
	if newBitLength > c.BitLength {
		// See if we need to extend the byte array.
		newNbBytesNeeded := (newBitLength-1)/8 + 1
		for ; len(c.Bytes) < newNbBytesNeeded; c.Bytes = append(c.Bytes, 0) {
		}
		c.BitLength = newBitLength
	}

	// Set the desired bit to 1.
	ct := uint(conditionType)
	byteNumber := ct / 8
	c.Bytes[byteNumber] |= 1 << ct % 8
}

// AddAll adds all the condition types from other to this set.
func (c *ConditionTypeSet) AddAll(other *ConditionTypeSet) {
	// New bit length is the higher one of both.
	c.BitLength = max(c.BitLength, other.BitLength)

	// We can add them together by binary ORing all bytes and copying bytes from other if it is longer.
	for i, b := range other.Bytes {
		if i < len(c.Bytes) {
			c.Bytes[i] |= b
		} else {
			c.Bytes = append(c.Bytes, b)
		}
	}
}

// addElement adds all the relevant condition types of the element to the condition type set.
// Accepted objects are Condition, Fulfillment and compoundConditionFulfillment.
func (c *ConditionTypeSet) addRelevant(element interface{}) {
	switch element.(type) {
	case Fulfillment:
		ff := element.(Fulfillment)
		c.Add(ff.ConditionType())
		switch element.(type) {
		case compoundConditionFulfillment:
			ff := element.(compoundConditionFulfillment)
			c.AddAll(ff.subConditionTypeSet())
		}
	case Condition:
		cond := element.(Condition)
		c.Add(cond.Type())
		c.AddAll(cond.SubTypes())
	}
}

type Condition interface {
	// Type returns the type of this condition.
	Type() ConditionType
	// Fingerprint returns the fingerprint of this condition.
	Fingerprint() []byte
	// MaxFulfillmentLength returns the maximum size of an encoded fulfillment for this condition.
	MaxFulfillmentLength() int
	// SubTypes returns the condition types of the sub-conditions of this condition.
	SubTypes() *ConditionTypeSet
	// Equals checks if this condition equals the other.
	Equals(Condition) bool
}

func NewSimpleCondition(conditionType ConditionType, fingerprint []byte, maxFulfillmentLength int) Condition {
	return &simpleCondition{
		TypeF:                 conditionType,
		FingerprintF:          fingerprint,
		MaxFulfillmentLengthF: maxFulfillmentLength,
	}
}

func NewCompoundCondition(conditionType ConditionType,
	fingerprint []byte,
	maxFulfillmentLength int,
	subTypes *ConditionTypeSet) Condition {
	return &compoundCondition{
		simpleCondition: simpleCondition{
			TypeF:                 conditionType,
			FingerprintF:          fingerprint,
			MaxFulfillmentLengthF: maxFulfillmentLength,
		},
		SubTypesF: subTypes,
	}
}

// simpleCondition represents a Condition that does not consist of sub-conditions.
type simpleCondition struct {
	TypeF                 ConditionType `asn:"-"`
	FingerprintF          []byte
	MaxFulfillmentLengthF int
}

func (c *simpleCondition) Type() ConditionType {
	return c.TypeF
}

func (c *simpleCondition) Fingerprint() []byte {
	return c.FingerprintF
}

func (c *simpleCondition) MaxFulfillmentLength() int {
	return c.MaxFulfillmentLengthF
}

func (c *simpleCondition) SubTypes() *ConditionTypeSet {
	return nil
}

func (c *simpleCondition) Equals(other Condition) bool {
	switch other.(type) {
	case *simpleCondition:
		return c.Type() == other.Type() &&
			bytes.Equal(c.Fingerprint(), other.Fingerprint()) &&
			c.MaxFulfillmentLength() == other.MaxFulfillmentLength()
	default:
		return false
	}
}

func (c *simpleCondition) String() string {
	uri, err := Uri(c)
	if err != nil {
		return "!Could not generate Condition's URI!"
	}
	return uri
}

// compoundCondition represents a Condition that does consist of sub-conditions.
type compoundCondition struct {
	simpleCondition
	SubTypesF *ConditionTypeSet
}

func (c *compoundCondition) SubTypes() *ConditionTypeSet {
	return c.SubTypesF
}

func (c *compoundCondition) Equals(other Condition) bool {
	switch other.(type) {
	case *compoundCondition:
		return c.Type() == other.Type() &&
			bytes.Equal(c.Fingerprint(), other.Fingerprint()) &&
			c.MaxFulfillmentLength() == other.MaxFulfillmentLength() &&
			c.SubTypes().Equals(other.SubTypes())
	default:
		return false
	}
}

func (c *compoundCondition) String() string {
	uri, err := Uri(c)
	if err != nil {
		return "!Could not generate Condition's URI!"
	}
	return uri
}
