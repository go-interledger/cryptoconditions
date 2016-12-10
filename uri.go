package cryptoconditions

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// minUriLength is the minimal size of a valid URI.
var minUriLength = min(minUriLengthCondition, minUriLengthFulfillment)

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
		base64.StdEncoding.EncodeToString(c.Fingerprint),
		c.MaxFulfillmentLength)
}

// fulfillmentUri builds a URI for a Fulfillment.
func generateFulfillmentUri(ff Fulfillment) (string, error) {
	payloadBytes, err := ff.Payload()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("cf:%x:%s",
		ff.Type(),
		base64.StdEncoding.EncodeToString(payloadBytes)), nil
}

// ParseUri parses a URI into an object.
// Will either return
// - a *Condition  if the prefix is "cc"
// - a Fulfillment if the prefux is "cf"
func ParseUri(uri string) (interface{}, error) {
	if len(uri) < minUriLength {
		return nil, errors.New("URI is too short to be valid.")
	}

	parts := strings.Split(uri, ":")
	switch parts[0] {
	case uriPrefixCondition:
		return parseConditionUriParts(parts)
	case uriPrefixFulfillment:
		return parseFulfillmentUriParts(parts)
	default:
		return nil, fmt.Errorf("Unknown URI prefix: %s", parts[0])
	}
}

// parseConditionUriParts builds a *Condition from a segmented URI.
func parseConditionUriParts(parts []string) (*Condition, error) {
	if len(parts) != 5 {
		return nil, errors.New("A Condition URI must consist of 5 segments.")
	}

	c := new(Condition)
	var err error
	if tp, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
		c.Type = ConditionType(tp)
	} else {
		return nil, err
	}
	if features, err := strconv.ParseUint(parts[2], 16, 8); err == nil {
		c.Features = Features(features)
	} else {
		return nil, err
	}
	if c.Fingerprint, err = base64.StdEncoding.DecodeString(parts[3]); err != nil {
		return nil, err
	}
	if mfl, err := strconv.ParseUint(parts[4], 10, 32); err == nil {
		c.MaxFulfillmentLength = uint32(mfl)
	} else {
		return nil, err
	}

	return c, nil
}

// parseFulfillmentUriParts builds a Fulfillment from a segmented URI.
func parseFulfillmentUriParts(parts []string) (Fulfillment, error) {
	if len(parts) != 3 {
		return nil, errors.New("A Fulfillment URI must consist of 3 segments.")
	}

	var err error
	var conditionType ConditionType
	if ct, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
		conditionType = ConditionType(ct)
	} else {
		return nil, err
	}

	ff, err := newFulfillmentByType(conditionType)
	if err != nil {
		return nil, err
	}

	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if err := ff.ParsePayload(payload); err != nil {
		return nil, err
	}

	return ff, nil
}
