package cryptoconditions

import "fmt"

type Fulfillment interface {
	// The condition type this fulfillment is intended for.
	Type() ConditionType

	// Generate condition.
	Condition() (*Condition, error)

	// Construct the fulfillment payload.
	Payload() ([]byte, error)

	// Populate this fulfillment from the payload.
	ParsePayload([]byte) error

	// Validate returns nil if the message is successfully validated by the Fullfillment.
	//TODO consider returning just bool and representing any underlying error as false
	Validate([]byte) error
}

// newFulfillmentByType creates an empty fulfillment object corresponding to the given type.
func newFulfillmentByType(conditionType ConditionType) (Fulfillment, error) {
	var ff Fulfillment
	switch conditionType {
	case CTEd25519:
		ff = new(FfEd25519)
	case CTPrefixSha256:
		ff = new(FfPrefixSha256)
	case CTPreimageSha256:
		ff = new(FfPrefixSha256)
	case CTRsaSha256:
		ff = new(FfRsaSha256)
	case CTThresholdSha256:
		ff = new(FfThresholdSha256)
	default:
		return nil, fmt.Errorf("Unknown condition type: %v", conditionType)
	}
	return ff, nil
}
