package cryptoconditions

import "crypto/sha256"

const (
	ffPreimageSha256Features Features = FSha256 | FPreimage
)

// FfPreimageSha256 implements the Preimage-SHA-256 fulfillment.
type FfPreimageSha256 struct {
	preimage []byte
}

// NewFfPreimageSha256 creates a new FfPreimageSha256 fulfillment.
func NewFfPreimageSha256(preimage []byte) *FfPreimageSha256 {
	return &FfPreimageSha256{
		preimage: preimage,
	}
}

func (ff *FfPreimageSha256) Type() ConditionType {
	return CTPreimageSha256
}

// Preimage returns the preimage used in this fulfillment.
func (ff *FfPreimageSha256) Preimage() []byte {
	return ff.preimage
}

func (ff *FfPreimageSha256) Payload() ([]byte, error) {
	return ff.preimage, nil
}

func (ff *FfPreimageSha256) ParsePayload(payload []byte) error {
	ff.preimage = payload
	return nil
}

func (ff *FfPreimageSha256) Condition() (*Condition, error) {
	fingerprint := sha256.Sum256(ff.preimage)
	maxFfLength := uint32(len(ff.preimage))

	return NewCondition(ff.Type(), ffPreimageSha256Features, fingerprint[:], maxFfLength), nil
}

func (ff *FfPreimageSha256) Validate(message []byte) error {
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
