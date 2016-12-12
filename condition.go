package cryptoconditions

import "bytes"

type ConditionType uint16

const (
	CTPreimageSha256 ConditionType = iota

	CTPrefixSha256

	CTThresholdSha256

	CTRsaSha256

	CTEd25519

	// unknownConditionType is used to see if a type integer is a known one (all smaller ones are known)
	unknownConditionType
)

// Condition is a struct that represents a condition.
// Conditions are considered immutable, so it's inadvisable to alter them.
type Condition struct {
	Type                 ConditionType
	Features             Features
	Fingerprint          []byte
	MaxFulfillmentLength uint32
}

// Create a new Condition.
func NewCondition(t ConditionType, features Features, fingerprint []byte, maxFulfillmentLength uint32) *Condition {
	return &Condition{
		Type:                 t,
		Features:             features,
		Fingerprint:          fingerprint,
		MaxFulfillmentLength: maxFulfillmentLength,
	}
}

// Equivalent checks if this condition equals the other.
func (c *Condition) Equals(other *Condition) bool {
	return c.Type == other.Type &&
		c.Features == other.Features &&
		bytes.Equal(c.Fingerprint, other.Fingerprint) &&
		c.MaxFulfillmentLength == other.MaxFulfillmentLength
}

func (c *Condition) String() string {
	uri, err := Uri(c)
	if err != nil {
		return "!Could not generate Condition's URI!"
	}
	return uri
}
