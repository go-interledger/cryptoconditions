package cryptoconditions

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
	"github.com/stevenroose/asn1"
)

//TODO IMPLICIT TAGGING
// Because our ASN.1 package does not support implicit tagging, we manually
// tag all values in all structs.  Normally, a flag IMPLICIT on the choices for
// conditions and fulfillments should make it possible to remove that manual
// tag numbers.

// ASN1Context defines the ASN.1 context that is used to encode and decode
// objects.  It explicitly requires encoding and decoding to happen in strict
// DER format and it also defines the CHOICE mapping for
// fulfillments (`fulfillment`) and conditions (`condition`).
var ASN1Context *asn1.Context

type encodedEd25519Sha256 struct {
	Fingerprint []byte `asn1:"tag:0"`
	Cost        int    `asn1:"tag:1"`
}

type encodedPrefixSha256 struct {
	Fingerprint []byte         `asn1:"tag:0"`
	Cost        int            `asn1:"tag:1"`
	SubTypes    asn1.BitString `asn1:"tag:2"`
}

type encodedPreimageSha256 struct {
	Fingerprint []byte `asn1:"tag:0"`
	Cost        int    `asn1:"tag:1"`
}

type encodedRsaSha256 struct {
	Fingerprint []byte `asn1:"tag:0"`
	Cost        int    `asn1:"tag:1"`
}

type encodedThresholdSha256 struct {
	Fingerprint []byte         `asn1:"tag:0"`
	Cost        int            `asn1:"tag:1"`
	SubTypes    asn1.BitString `asn1:"tag:2"`
}

func encodedCondition(condition Condition) interface{} {
	switch condition.Type() {
	case CTEd25519Sha256:
		return encodedEd25519Sha256{
			Fingerprint: condition.Fingerprint(),
			Cost:        condition.Cost(),
		}

	case CTPrefixSha256:
		return encodedPrefixSha256{
			Fingerprint: condition.Fingerprint(),
			Cost:        condition.Cost(),
			SubTypes:    asn1.BitString(condition.SubTypes()),
		}

	case CTPreimageSha256:
		return encodedPreimageSha256{
			Fingerprint: condition.Fingerprint(),
			Cost:        condition.Cost(),
		}

	case CTRsaSha256:
		return encodedRsaSha256{
			Fingerprint: condition.Fingerprint(),
			Cost:        condition.Cost(),
		}

	case CTThresholdSha256:
		return encodedThresholdSha256{
			Fingerprint: condition.Fingerprint(),
			Cost:        condition.Cost(),
			SubTypes:    asn1.BitString(condition.SubTypes()),
		}
	}
	return nil
}

// encodeCondition encodes the given condition to it's DER encoding.
func encodeCondition(condition Condition) ([]byte, error) {
	var encoded = encodedCondition(condition)

	//TODO determine when an error is possible
	encoding, err := ASN1Context.EncodeWithOptions(encoded, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoding, nil
}

// DecodeCondition decodes the DER encoding of a condition.
func DecodeCondition(encodedCondition []byte) (Condition, error) {
	var obj interface{}
	rest, err := ASN1Context.DecodeWithOptions(
		encodedCondition, &obj, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return nil, errors.Errorf(
			"Encoding was not minimal. Excess bytes: %x", rest)
	}

	var cond Condition
	switch obj.(type) {
	case encodedEd25519Sha256:
		c := obj.(encodedEd25519Sha256)
		cond = NewSimpleCondition(CTEd25519Sha256, c.Fingerprint, c.Cost)
	case encodedPrefixSha256:
		c := obj.(encodedPrefixSha256)
		cond = NewCompoundCondition(CTPrefixSha256, c.Fingerprint, c.Cost, ConditionTypeSet(c.SubTypes))
	case encodedPreimageSha256:
		c := obj.(encodedPreimageSha256)
		cond = NewSimpleCondition(CTPreimageSha256, c.Fingerprint, c.Cost)
	case encodedRsaSha256:
		c := obj.(encodedRsaSha256)
		cond = NewSimpleCondition(CTRsaSha256, c.Fingerprint, c.Cost)
	case encodedThresholdSha256:
		c := obj.(encodedThresholdSha256)
		cond = NewCompoundCondition(CTThresholdSha256, c.Fingerprint, c.Cost, ConditionTypeSet(c.SubTypes))

	default:
		return nil, errors.New("encoding was not a condition")
	}

	return cond, nil
}

// encodeFulfillment encodes the given fulfillment to it's DER encoding.
func encodeFulfillment(fulfillment Fulfillment) ([]byte, error) {
	//TODO determine when an error is possible
	encoded, err := ASN1Context.EncodeWithOptions(
		fulfillment, "choice:fulfillment")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoded, nil
}

// DecodeFulfillment decodes the DER encoding of a fulfillment.
func DecodeFulfillment(encodedFulfillment []byte) (Fulfillment, error) {
	var obj interface{}
	rest, err := ASN1Context.DecodeWithOptions(
		encodedFulfillment, &obj, "choice:fulfillment")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return nil, errors.Errorf(
			"Encoding was not minimal. Excess bytes: %x", rest)
	}

	// Do some reflection magic to derive a pointer to the struct in obj.
	ptr := reflect.Indirect(reflect.New(reflect.TypeOf(obj)))
	ptr.Set(reflect.ValueOf(obj))
	obj = ptr.Addr().Interface()

	// Check whether the object we got is in fact a Fulfillment.
	fulfillment, ok := obj.(Fulfillment)
	if !ok {
		return nil, errors.New("Encoded object was not a fulfillment")
	}
	return fulfillment, nil
}

// buildAsn1Context builds the context for ASN.1 encoding and decoding.
// It forces the use of DER and specifies the tags for the CHOICES used for
// conditions and fulfillments.
func buildASN1Context() *asn1.Context {
	ctx := asn1.NewContext()
	ctx.SetDer(true, true)

	// Define the Condition CHOICE element.
	conditionChoices := []asn1.Choice{
		{
			Options: fmt.Sprintf("tag:%d", CTEd25519Sha256),
			Type:    reflect.TypeOf(encodedEd25519Sha256{}),
		},
		{
			Options: fmt.Sprintf("tag:%d", CTPrefixSha256),
			Type:    reflect.TypeOf(encodedPrefixSha256{}),
		},
		{
			Options: fmt.Sprintf("tag:%d", CTPreimageSha256),
			Type:    reflect.TypeOf(encodedPreimageSha256{}),
		},
		{
			Options: fmt.Sprintf("tag:%d", CTRsaSha256),
			Type:    reflect.TypeOf(encodedRsaSha256{}),
		},
		{
			Options: fmt.Sprintf("tag:%d", CTThresholdSha256),
			Type:    reflect.TypeOf(encodedThresholdSha256{}),
		},
	}
	if err := ctx.AddChoice("condition", conditionChoices); err != nil {
		panic(err)
	}

	// Define the Fulfillment CHOICE element.
	fulfillmentChoices := make([]asn1.Choice, nbKnownConditionTypes)
	for ct, ffType := range fulfillmentTypeMap {
		tag := fmt.Sprintf("tag:%d", ct)
		fulfillmentChoices[ct] = asn1.Choice{Options: tag, Type: ffType}
	}
	if err := ctx.AddChoice("fulfillment", fulfillmentChoices); err != nil {
		panic(err)
	}

	return ctx
}

func init() {
	ASN1Context = buildASN1Context()
}
