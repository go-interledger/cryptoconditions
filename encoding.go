package cryptoconditions

import (
	"fmt"

	"github.com/PromonLogicalis/asn1"
	"github.com/pkg/errors"
)

// Asn1Context defines the ASN.1 context that is used to encode and decode objects.
// It explicitly requires encoding and decoding to happen in strict DER format and it also defines the CHOICE mapping
// for fulfillments (`fulfillment`) and conditions (`condition`).
var Asn1Context = buildAsn1Context()

func EncodeCondition(condition Condition) ([]byte, error) {
	//TODO determine when an error is possible
	encoded, err := Asn1Context.EncodeWithOptions(condition, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoded, nil
}

func DecodeCondition(encodedCondition []byte) (Condition, error) {
	var cond interface{}
	rest, err := Asn1Context.DecodeWithOptions(encodedCondition, &cond, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("Encoding was not minimal. Excess bytes: %x", rest)
	}
	switch cond.(type) {
	case simpleCondition:
		condition := cond.(simpleCondition)
		return &condition, nil
	case compoundCondition:
		condition := cond.(compoundCondition)
		return &condition, nil
	default:
		return nil, errors.New("Encoded object was not a condition")
	}
}

func EncodeFulfillment(fulfillment Fulfillment) ([]byte, error) {
	//TODO determine when an error is possible
	encoded, err := Asn1Context.EncodeWithOptions(fulfillment, "choice:fulfillment")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoded, nil
}

func DecodeFulfillment(encodedFulfillment []byte) (Fulfillment, error) {
	var ff interface{}
	rest, err := Asn1Context.DecodeWithOptions(encodedFulfillment, &ff, "choice:fulfillment")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("Encoding was not minimal. Excess bytes: %x", rest)
	}
	fmt.Printf("%T\n", ff)
	fulfillment, ok := ff.(Fulfillment)
	if !ok {
		return nil, errors.New("Encoded object was not a fulfillment")
	}
	return fulfillment, nil
}

func buildAsn1Context() *asn1.Context {
	ctx := asn1.NewContext()
	// Enforce DER encoding and decoding.
	ctx.SetDer(true, true)

	// Define the Condition CHOICE element.
	conditionChoices := make([]asn1.Choice, nbKnownConditionTypes)
	for ct, condType := range conditionTypeMap {
		tag := fmt.Sprintf("tag:%v", ct)
		conditionChoices[ct] = asn1.Choice{Options: tag, Type: condType}
	}
	if err := ctx.AddChoice("condition", conditionChoices); err != nil {
		panic(err)
	}

	// Define the Fulfillment CHOICE element.
	fulfillmentChoices := make([]asn1.Choice, nbKnownConditionTypes)
	for ct, ffType := range fulfillmentTypeMap {
		tag := fmt.Sprintf("tag:%v", ct)
		fulfillmentChoices[ct] = asn1.Choice{Options: tag, Type: ffType}
	}
	if err := ctx.AddChoice("fulfillment", fulfillmentChoices); err != nil {
		panic(err)
	}

	return ctx
}
