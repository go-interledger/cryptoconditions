package cryptoconditions

import "crypto/sha256"

// FfPreimageSha256 implements the PREIMAGE-SHA-256 fulfillment.
type FfPreimageSha256 struct {
	Preimage []byte
}

// PreimageSha256 creates a new PREIMAGE-SHA-256 fulfillment.
func PreimageSha256(preimage []byte) *FfPreimageSha256 {
	return &FfPreimageSha256{
		Preimage: preimage,
	}
}

func (ff *FfPreimageSha256) ConditionType() ConditionType {
	return CTPreimageSha256
}

func (ff *FfPreimageSha256) Condition() Condition {
	return NewSimpleCondition(ff.ConditionType(), ff.fingerprint(), ff.maxFulfillmentLength())
}

func (ff *FfPreimageSha256) fingerprint() []byte {
	hash := sha256.Sum256(ff.Preimage)
	return hash[:]
}

func (ff *FfPreimageSha256) maxFulfillmentLength() int {
	return len(ff.Preimage)
}

func (ff *FfPreimageSha256) Validate(condition Condition, message []byte) error {
	if !matches(ff, condition) {
		return fulfillmentDoesNotMatchConditionError
	}

	// For a preimage fulfillment, no additional check is required.
	return nil
}

func (ff *FfPreimageSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}
