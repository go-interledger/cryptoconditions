package cryptoconditions

import (
	"bytes"

	"fmt"

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

// conditionTypeDictionary maps condition type names to the corresponding
// condition types.
var conditionTypeDictionary = map[string]ConditionType{
	"ED25519-SHA-256":   CTEd25519Sha256,
	"PREFIX-SHA-256":    CTPrefixSha256,
	"PREIMAGE-SHA-256":  CTPreimageSha256,
	"THRESHOLD-SHA-256": CTThresholdSha256,
	"RSA-SHA-256":       CTRsaSha256,
}

func (t ConditionType) IsCompound() bool {
	switch t {
	case CTEd25519Sha256:
		return false
	case CTPrefixSha256:
		return true
	case CTPreimageSha256:
		return false
	case CTRsaSha256:
		return false
	case CTThresholdSha256:
		return true
	}
	panic(fmt.Sprintf("ConditionType %d does not exist", t))
}

func (t ConditionType) String() string {
	switch t {
	case CTEd25519Sha256:
		return "ED25519-SHA-256"
	case CTPrefixSha256:
		return "PREFIX-SHA-256"
	case CTPreimageSha256:
		return "PREIMAGE-SHA-256"
	case CTThresholdSha256:
		return "THRESHOLD-SHA-256"
	case CTRsaSha256:
		return "RSA-SHA-256"
	}
	panic(fmt.Sprintf("ConditionType %d does not exist", t))
}

// ConditionTypeSet represents a set of ConditionTypes.
// It is represented as an ASN.1 BIT STRING like defined in the specification.
type ConditionTypeSet asn1.BitString

// Has determines if the given condition type is present.
func (c ConditionTypeSet) Has(conditionType ConditionType) bool {
	return asn1.BitString(c).At(int(conditionType)) == 1
}

func (c ConditionTypeSet) AllTypes() []ConditionType {
	all := make([]ConditionType, 0, nbKnownConditionTypes)
	if c.Has(CTEd25519Sha256) {
		all = append(all, CTEd25519Sha256)
	}
	if c.Has(CTPrefixSha256) {
		all = append(all, CTPrefixSha256)
	}
	if c.Has(CTPreimageSha256) {
		all = append(all, CTPreimageSha256)
	}
	if c.Has(CTRsaSha256) {
		all = append(all, CTRsaSha256)
	}
	if c.Has(CTThresholdSha256) {
		all = append(all, CTThresholdSha256)
	}
	return all
}

// Equals returns true if `other` represents the same condition type set as
// this. False otherwise.
func (c ConditionTypeSet) Equals(other ConditionTypeSet) bool {
	return bytes.Equal(c.Bytes, other.Bytes) && c.BitLength == other.BitLength
}

// Add adds the given condition type to the set.
func (c *ConditionTypeSet) add(conditionType ConditionType) {
	newBitLength := max(c.BitLength, int(conditionType)+1)
	if newBitLength > c.BitLength {
		// See if we need to extend the byte array.
		newNbBytes := (newBitLength-1)/8 + 1
		if newNbBytes > len(c.Bytes) {
			c.Bytes = append(c.Bytes, make([]byte, newNbBytes-len(c.Bytes))...)
		}
		c.BitLength = newBitLength
	}

	// Set the desired bit to 1.
	ct := uint(conditionType)
	byteNumber := ct / 8
	m := ct % 8
	c.Bytes[byteNumber] |= 1 << (7 - m)
}

// AddAll adds all the condition types from other to this set.
func (c *ConditionTypeSet) merge(other ConditionTypeSet) {
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
}

// addElement adds all the relevant condition types of the element to the
// condition type set.
// Accepted objects are Condition, Fulfillment and compoundConditionFulfillment.
func (c *ConditionTypeSet) addRelevant(element interface{}) {
	switch element.(type) {
	case Fulfillment:
		ff := element.(Fulfillment)
		c.add(ff.ConditionType())
		if compound, ok := element.(compoundConditionFulfillment); ok {
			c.merge(compound.subConditionsTypeSet())
		}
	case Condition:
		cond := element.(Condition)
		c.add(cond.Type())
		c.merge(cond.SubTypes())
	}
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

type Cond struct {
	conditionType ConditionType

	fingerprint []byte
	cost        int

	subTypes ConditionTypeSet
}

func NewSimpleCondition(conditionType ConditionType, fingerprint []byte, cost int) Condition {
	return &Cond{
		conditionType: conditionType,
		fingerprint:   fingerprint,
		cost:          cost,
		subTypes:      ConditionTypeSet{},
	}
}

func NewCompoundCondition(conditionType ConditionType, fingerprint []byte, cost int, subTypes ConditionTypeSet) Condition {
	return &Cond{
		conditionType: conditionType,
		fingerprint:   fingerprint,
		cost:          cost,
		subTypes:      subTypes,
	}
}

func newConditionFromFulfillment(ff Fulfillment) Condition {
	c := &Cond{
		conditionType: ff.ConditionType(),
		fingerprint:   ff.fingerprint(),
		cost:          ff.cost(),
	}

	if compound, ok := ff.(compoundConditionFulfillment); ok {
		c.subTypes = compound.subConditionsTypeSet()
	}

	return c
}

// Type returns the type of this condition.
func (c *Cond) Type() ConditionType {
	return c.conditionType
}

// Fingerprint returns the fingerprint of this condition.
func (c *Cond) Fingerprint() []byte {
	return c.fingerprint
}

// Cost returns the cost metric of a fulfillment for this condition.
func (c *Cond) Cost() int {
	return c.cost
}

// SubTypes returns the condition types of the
// sub-conditions of this condition.
func (c *Cond) SubTypes() ConditionTypeSet {
	return c.subTypes
}

// Equals checks if this condition equals the other.
func (c *Cond) Equals(other Condition) bool {
	return c.Type() == other.Type() &&
		bytes.Equal(c.fingerprint, other.Fingerprint()) &&
		c.Cost() == other.Cost() &&
		c.SubTypes().Equals(other.SubTypes())
}

// URI returns the URI for this condition.
func (c *Cond) URI() string {
	return generateURI(c)
}

// Encode encodes the condition in binary format.
func (c *Cond) Encode() ([]byte, error) {
	return encodeCondition(c)
}
