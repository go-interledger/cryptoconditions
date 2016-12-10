package cryptoconditions

type ConditionType uint16

const (
	CTPreimageSha256 ConditionType = iota

	CTPrefixSha256

	CTThresholdSha256

	CTRsaSha256

	CTEd25519
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

func (c *Condition) String() string {
	uri, _ := Uri(c)
	return uri
}
