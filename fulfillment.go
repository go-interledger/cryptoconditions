package cryptoconditions

import (
	"fmt"

	"reflect"

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

// compoundConditionFulfillment is an interface that fulfillments for compound conditions have to implement to be able
// to indicate the condition types of their sub-fulfillments.
type compoundConditionFulfillment interface {
	subConditionTypeSet() *ConditionTypeSet
}

// fulfillmentTypeMap maps ConditionTypes to the corresponding Go type for the fulfillment for that condition.
var fulfillmentTypeMap = map[ConditionType]reflect.Type{
	CTEd25519:         reflect.TypeOf(FfEd25519{}),
	CTPrefixSha256:    reflect.TypeOf(FfPrefixSha256{}),
	CTPreimageSha256:  reflect.TypeOf(FfPreimageSha256{}),
	CTRsaSha256:       reflect.TypeOf(FfRsaSha256{}),
	CTThresholdSha256: reflect.TypeOf(FfThresholdSha256{}),
}

var fulfillmentDoesNotMatchConditionError = errors.New("The fulfillment does not match the given condition")

// newFulfillmentByType creates an empty fulfillment object corresponding to the given type.
func newFulfillmentByType(conditionType ConditionType) (Fulfillment, error) {
	ffType, ok := fulfillmentTypeMap[conditionType]
	if !ok {
		return nil, fmt.Errorf("Unknown condition type: %v", conditionType)
	}
	return reflect.New(ffType).Interface().(Fulfillment), nil
}
