package cryptoconditions

import (
	"bytes"
	"reflect"

	"github.com/stevenroose/asn1"
)

// ConditionType represent one of the predefined condition types in the
// specification.
type ConditionType int

// All the condition types and their corresponding type codes.
const (
	// PREIMAGE-SHA-256
	CTPreimageSha256 ConditionType = iota
	// PREFIX-SHA-256
	CTPrefixSha256
	// THRESHOLD-SHA-256
	CTThresholdSha256
	// RSA-SHA-256
	CTRsaSha256
	// ED25519
	CTEd25519Sha256

	// nbKnownConditionTypes is the number of known condition types.
	// Assuming all code up till this number are known, comparing a code with
	// nbKnownConditionTypes determines whether the code is known or not.
	// This number should always be equal to
	// `len(conditionTypeMap)` and `len(fulfillmentTypeMap)`.
	nbKnownConditionTypes
)

// conditionTypeNames maps condition types to their human-readable names.
// We use the names as they appear in the type registry section of the
// specification.
var conditionTypeNames = map[ConditionType]string{
	CTEd25519Sha256:   "ED25519",
	CTPrefixSha256:    "PREFIX-SHA-256",
	CTPreimageSha256:  "PREIMAGE-SHA-256",
	CTThresholdSha256: "THRESHOLD-SHA-256",
	CTRsaSha256:       "RSA-SHA-256",
}

// conditionTypeDictionary maps condition type names to the corresponding
// condition types.
var conditionTypeDictionary = map[string]ConditionType{
	"ED25519":           CTEd25519Sha256,
	"PREFIX-SHA-256":    CTPrefixSha256,
	"PREIMAGE-SHA-256":  CTPreimageSha256,
	"THRESHOLD-SHA-256": CTThresholdSha256,
	"RSA-SHA-256":       CTRsaSha256,
}

func (ct ConditionType) String() string {
	return conditionTypeNames[ct]
}

// Define these two types so that we don't have to call
// reflect.TypeOf for every type.
var simpleConditionType, compoundConditionType = reflect.TypeOf(simpleCondition{}), reflect.TypeOf(compoundCondition{})

// conditionTypeMap is a map that maps every ConditionType to either
// the Go type for simpleCondition or compoundCondition.
var conditionTypeMap = map[ConditionType]reflect.Type{
	CTEd25519Sha256:   simpleConditionType,
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

// Equals returns true if `other` represents the same condition type set as
// this. False otherwise.
func (c ConditionTypeSet) Equals(other ConditionTypeSet) bool {
	return bytes.Equal(c.Bytes, other.Bytes) && c.BitLength == other.BitLength
}

// Add adds the given condition type to the set.
func (c ConditionTypeSet) Add(conditionType ConditionType) ConditionTypeSet {
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

	return c
}

// AddAll adds all the condition types from other to this set.
func (c ConditionTypeSet) AddAll(other ConditionTypeSet) ConditionTypeSet {
	// New bit length is the higher one of both.
	c.BitLength = max(c.BitLength, other.BitLength)

	// We can add them together by binary ORing all bytes and copying bytes
	// from other if it is longer.
	for i, b := range other.Bytes {
		if i < len(c.Bytes) {
			c.Bytes[i] |= b
		} else {
			c.Bytes = append(c.Bytes, b)
		}
	}

	return c
}

// addElement adds all the relevant condition types of the element to the
// condition type set.
// Accepted objects are Condition, Fulfillment and compoundConditionFulfillment.
func (c ConditionTypeSet) addRelevant(element interface{}) ConditionTypeSet {
	switch element.(type) {
	case Fulfillment:
		ff := element.(Fulfillment)
		c = c.Add(ff.ConditionType())
		if compound, ok := element.(compoundConditionFulfillment); ok {
			c = c.AddAll(compound.subConditionsTypeSet())
		}
	case Condition:
		cond := element.(Condition)
		c = c.Add(cond.Type())
		c = c.AddAll(cond.SubTypes())
	}

	return c
}

// Condition defines the condition interface.
type Condition interface {
	// Type returns the type of this condition.
	Type() ConditionType
	// Fingerprint returns the fingerprint of this condition.
	Fingerprint() []byte
	// Cost returns the cost metric of a fulfillment for this condition.
	Cost() int
	// SubTypes returns the condition types of the
	// sub-conditions of this condition.
	SubTypes() ConditionTypeSet
	// Equals checks if this condition equals the other.
	Equals(Condition) bool
	// URI returns the URI for this condition.
	URI() string
	// Encode encodes the condition in binary format.
	Encode() ([]byte, error)
}

// simpleCondition represents a Condition that
// does not consist of sub-conditions.
type simpleCondition struct {
	TypeF        ConditionType `asn1:"-"`
	FingerprintF []byte        `asn1:"tag:0"`
	CostF        int           `asn1:"tag:1"`
}

//TODO consider not having these methods. It makes little sense for users to create loose conditions instead of
// deriving them from a fulfillment.

// NewSimpleCondition creates a new simple condition.
func NewSimpleCondition(conditionType ConditionType, fingerprint []byte, cost int) Condition {
	return &simpleCondition{
		TypeF:        conditionType,
		FingerprintF: fingerprint,
		CostF:        cost,
	}
}

func (c *simpleCondition) Type() ConditionType {
	return c.TypeF
}

func (c *simpleCondition) Fingerprint() []byte {
	return c.FingerprintF
}

func (c *simpleCondition) Cost() int {
	return c.CostF
}

func (c *simpleCondition) SubTypes() ConditionTypeSet {
	return ConditionTypeSet{}
}

func (c *simpleCondition) Equals(other Condition) bool {
	if _, ok := other.(*simpleCondition); !ok {
		return false
	}
	return c.Type() == other.Type() &&
		bytes.Equal(c.Fingerprint(), other.Fingerprint()) &&
		c.Cost() == other.Cost()
}

func (c *simpleCondition) Encode() ([]byte, error) {
	return encodeCondition(c)
}

func (c *simpleCondition) URI() string { return generateURI(c) }

func (c *simpleCondition) String() string { return c.URI() }

// compoundCondition represents a Condition that
// does consist of sub-conditions.
type compoundCondition struct {
	TypeF        ConditionType  `asn1:"-"`
	FingerprintF []byte         `asn1:"tag:0"`
	CostF        int            `asn1:"tag:1"`
	SubTypesF    asn1.BitString `asn1:"tag:2"`
}

// NewCompoundCondition creates a new compound condition.
func NewCompoundCondition(conditionType ConditionType,
	fingerprint []byte, cost int,
	subTypes ConditionTypeSet) Condition {
	return &compoundCondition{
		TypeF:        conditionType,
		FingerprintF: fingerprint,
		CostF:        cost,
		SubTypesF:    asn1.BitString(subTypes),
	}
}

func (c *compoundCondition) Type() ConditionType {
	return c.TypeF
}

func (c *compoundCondition) Fingerprint() []byte {
	return c.FingerprintF
}

func (c *compoundCondition) Cost() int {
	return c.CostF
}

func (c *compoundCondition) SubTypes() ConditionTypeSet {
	return ConditionTypeSet(c.SubTypesF)
}

func (c *compoundCondition) Equals(other Condition) bool {
	if _, ok := other.(*compoundCondition); !ok {
		return false
	}

	return c.Type() == other.Type() &&
		bytes.Equal(c.Fingerprint(), other.Fingerprint()) &&
		c.Cost() == other.Cost() &&
		c.SubTypes().Equals(other.SubTypes())
}

func (c *compoundCondition) Encode() ([]byte, error) {
	return encodeCondition(c)
}

func (c *compoundCondition) URI() string { return generateURI(c) }

func (c *compoundCondition) String() string { return c.URI() }
