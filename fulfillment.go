package cryptoconditions

import (
	"fmt"

	"github.com/pkg/errors"
)

type Fulfillment interface {
	// The condition type this fulfillment is intended for.
	ConditionType() ConditionType

	// Generate condition.
	Condition() Condition
	//TODO consider moving Condition away from here because the next two can make up for it

	fingerprint() []byte

	maxFulfillmentLength() int

	// Validate returns nil if this fulfillment correctly validates the given condition.
	// The message parameter may be nil.
	//TODO consider returning just bool and representing any underlying error as false
	Validate(Condition, []byte) error
}

type compoundConditionFulfillment interface {
	subConditionTypeSet() *ConditionTypeSet
}

var fulfillmentDoesNotMatchConditionError = errors.New("The fulfillment does not match the given condition")

// newFulfillmentByType creates an empty fulfillment object corresponding to the given type.
func newFulfillmentByType(conditionType ConditionType) (Fulfillment, error) {
	var ff Fulfillment
	switch conditionType {
	case CTEd25519:
		ff = new(FfEd25519)
	case CTPrefixSha256:
		ff = new(FfPrefixSha256)
	case CTPreimageSha256:
		ff = new(FfPreimageSha256)
	case CTRsaSha256:
		ff = new(FfRsaSha256)
	case CTThresholdSha256:
		ff = new(FfThresholdSha256)
	default:
		return nil, fmt.Errorf("Unknown condition type: %v", conditionType)
	}
	return ff, nil
}
