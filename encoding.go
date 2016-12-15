package cryptoconditions

import (
	"fmt"
	"reflect"

	"github.com/PromonLogicalis/asn1"
)

// Asn1Context defines the ASN.1 context that is used to encode and decode objects.
// It explicitly requires encoding and decoding to happen in strict DER format and it also defines the CHOICE mapping
// for fulfillments (`fulfillment`) and conditions (`condition`).
var Asn1Context = buildAsn1Context()

func EncodeCondition(condition Condition) ([]byte, error) {
	//TODO determine when an error is possible
	encoded, err := Asn1Context.EncodeWithOptions(condition, "choice:condition")
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func EncodeFulfillment(fulfillment Fulfillment) ([]byte, error) {
	//TODO determine when an error is possible
	encoded, err := Asn1Context.EncodeWithOptions(fulfillment, "choice:fulfillment")
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func buildAsn1Context() *asn1.Context {
	ctx := asn1.NewContext()
	ctx.SetDer(true, true)

	// Define the Condition CHOICE element.
	simpleType := reflect.TypeOf(simpleCondition{})
	compoundType := reflect.TypeOf(compoundCondition{})
	conditionChoices := make([]asn1.Choice, nbKnownConditionTypes)
	for ct, isCompound := range conditionCompoundMap {
		tag := fmt.Sprintf("tag:%v", ct)
		if isCompound {
			conditionChoices[ct] = asn1.Choice{Options: tag, Type: compoundType}
		} else {
			conditionChoices[ct] = asn1.Choice{Options: tag, Type: simpleType}
		}
	}
	if err := ctx.AddChoice("condition", conditionChoices); err != nil {
		panic(err)
	}

	// Define the Fulfillment CHOICE element.
	fulfillmentChoices := []asn1.Choice{
		{
			Options: "tag:0",
			Type:    reflect.TypeOf(FfPreimageSha256{}),
		},
		{
			Options: "tag:1",
			Type:    reflect.TypeOf(FfPrefixSha256{}),
		},
		{
			Options: "tag:2",
			Type:    reflect.TypeOf(FfThresholdSha256{}),
		},
		{
			Options: "tag:3",
			Type:    reflect.TypeOf(FfRsaSha256{}),
		},
		{
			Options: "tag:4",
			Type:    reflect.TypeOf(FfEd25519{}),
		},
	}
	if err := ctx.AddChoice("fulfillment", fulfillmentChoices); err != nil {
		panic(err)
	}

	return ctx
}
