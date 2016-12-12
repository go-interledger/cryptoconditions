package cryptoconditions

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/kalaspuffar/base64url"
)

const (
	// Minimum URI length for a condition:
	// 2 prefix + 1 colon + 1 type + 1 colon + 1 features + 1 colon + 0 fingerprint + 1 colon + 1 max ff length
	//TODO is a 0 fingerprint valid?
	minUriLengthCondition = 9

	// Minimum URI length for a fulfillment:
	// 2 prefix + 1 colon + 1 type + 1 colon + 0 payload
	minUriLengthFulfillment = 5
)

const (
	uriPrefixCondition   = "cc"
	uriPrefixFulfillment = "cf"
)

// Uri generates a URI for the given object.
// Only objects of type *Condition and Fulfillment are allowed.
func Uri(obj interface{}) (string, error) {
	switch obj.(type) {
	case *Condition:
		return generateConditionUri(obj.(*Condition)), nil
	case Fulfillment:
		return generateFulfillmentUri(obj.(Fulfillment))
	}
	return "", errors.New("Unknown object type, cannot generate URI.")
}

// conditionUri builds a URI for a Condition.
func generateConditionUri(c *Condition) string {
	return fmt.Sprintf("cc:%x:%x:%s:%s",
		c.Type,
		c.Features,
		base64url.Encode(c.Fingerprint),
		c.MaxFulfillmentLength)
}

// fulfillmentUri builds a URI for a Fulfillment.
func generateFulfillmentUri(ff Fulfillment) (string, error) {
	payloadBytes, err := ff.Payload()
	if err != nil {
		return "", errors.Wrap(err, "Failed to generate fulfillment payload")
	}
	return fmt.Sprintf("cf:%x:%s",
		ff.Type(),
		base64url.Encode(payloadBytes)), nil
}

// ParseUri parses a URI into an object.
// Will either return
// - a *Condition  if the prefix is "cc"
// - a Fulfillment if the prefux is "cf"
func ParseUri(uri string) (interface{}, error) {
	parts := strings.Split(uri, ":")
	if len(parts) < 1 {
		return nil, errors.New("URI does not have a prefix.")
	}

	switch parts[0] {
	case uriPrefixCondition:
		return ParseConditionUri(uri)
	case uriPrefixFulfillment:
		return ParseFulfillmentUri(uri)
	default:
		return nil, fmt.Errorf("Unknown URI prefix: %s", parts[0])
	}
}

// ParseConditionUri parses a URI into a *Condition.
func ParseConditionUri(uri string) (*Condition, error) {
	if len(uri) < minUriLengthCondition {
		return nil, errors.New("URI is too short to be valid.")
	}

	parts := strings.Split(uri, ":")
	if len(parts) != 5 {
		return nil, errors.New("A Condition URI must consist of 5 segments.")
	}
	if parts[0] != uriPrefixCondition {
		return nil, fmt.Errorf("Wrong condition URI prefix: %s", parts[0])
	}

	condition := new(Condition)
	var err error
	if tp, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
		condition.Type = ConditionType(tp)
	} else {
		return nil, errors.Wrapf(err, "Failed to parse uint16 from hex '%v'", parts[1])
	}
	if features, err := strconv.ParseUint(parts[2], 16, 8); err == nil {
		condition.Features = Features(features)
	} else {
		return nil, errors.Wrapf(err, "Failed to parse uint8 from hex '%v'", parts[2])
	}
	if condition.Fingerprint, err = base64url.Decode(parts[3]); err != nil {
		return nil, errors.Wrapf(err, "Failed to decode base64url encoding '%v'", parts[3])
	}
	if mfl, err := strconv.ParseUint(parts[4], 10, 32); err == nil {
		condition.MaxFulfillmentLength = uint32(mfl)
	} else {
		return nil, errors.Wrapf(err, "Failed to parse uint32 from decimal '%v'", parts[4])
	}

	return condition, nil
}

// ParseFulfillmentUri parses a URI into a Fulfillment.
func ParseFulfillmentUri(uri string) (Fulfillment, error) {
	if len(uri) < minUriLengthFulfillment {
		return nil, errors.New("URI is too short to be valid.")
	}

	parts := strings.Split(uri, ":")
	if len(parts) != 3 {
		return nil, errors.New("A Fulfillment URI must consist of 3 segments.")
	}
	if parts[0] != uriPrefixFulfillment {
		return nil, fmt.Errorf("Wrong fulfillment URI prefix: %s", parts[0])
	}

	var conditionType ConditionType
	if ct, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
		conditionType = ConditionType(ct)
	} else {
		return nil, errors.Wrapf(err, "Failed to parse uint16 from hex '%v'", parts[1])
	}

	ff, err := newFulfillmentByType(conditionType)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create an empty fulfillment of type %v", conditionType)
	}

	payload, err := base64url.Decode(parts[2])
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to decode base64url encoding of '%v'", parts[2])
	}
	if err := ff.ParsePayload(payload); err != nil {
		return nil, errors.Wrap(err, "Failed to parse fulfillment payload")
	}

	return ff, nil
}
