package cryptoconditions

import (
	"io"

	"github.com/pkg/errors"
)

// DeserializeCondition reads a condition from the reader in binary format.
func DeserializeCondition(r io.Reader) (Condition, error) {
	var err error
	c := new(Condition)
	if c.Type, err = readConditionType(r); err != nil {
		return nil, errors.Wrap(err, "Failed to read condition type")
	}
	if c.Features, err = readFeatures(r); err != nil {
		return nil, errors.Wrap(err, "Failed to read feature bitmask")
	}
	if c.Fingerprint, err = readOctetString(r); err != nil {
		return nil, errors.Wrap(err, "Failed to read octet string for fingerprint")
	}
	if mff, err := readVarUInt(r); err != nil {
		return nil, errors.Wrap(err, "Failed to read VarUInt of max fulfillment length")
	} else {
		c.MaxFulfillmentLength = uint32(mff)
	}
	return c, nil
}

// SerializeCondition writes the condition to the writer in binary format.
func SerializeCondition(w io.Writer, c Condition) error {
	// write condition type
	if err := writeConditionType(w, c.Type); err != nil {
		return errors.Wrap(err, "Failed to write condition type")
	}
	// write features
	writeFeatures(w, c.Features)
	// write fingerprint
	if err := writeOctetString(w, c.Fingerprint); err != nil {
		return errors.Wrap(err, "Failed to write octet string of fingerprint")
	}
	// write max fulfillment length
	return errors.Wrap(writeVarUInt(w, int(c.MaxFulfillmentLength)),
		"Failed to write VarUInt of max fulfillment length")
}

// SerializeFulfillment reads a fulfillment from the reader in binary format.
func DeserializeFulfillment(r io.Reader) (Fulfillment, error) {
	// read condition type and payload
	conditionType, err := readConditionType(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read condition type")
	}
	payload, err := readOctetString(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read payload")
	}

	ff, err := newFulfillmentByType(conditionType)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create an empty fulfillment of condition type %v", conditionType)
	}
	if err := ff.ParsePayload(payload); err != nil {
		return nil, errors.Wrap(err, "Failed to parse fulfillment payload")
	}

	return ff, nil
}

// SerializeFulfillment writes the fulfillment to the writer in binary format.
func SerializeFulfillment(w io.Writer, ff Fulfillment) error {
	if err := writeConditionType(w, ff.ConditionType()); err != nil {
		return errors.Wrap(err, "Failed to write condition type")
	}
	payload, err := ff.Payload()
	if err != nil {
		return errors.Wrap(err, "Failed to generate fulfillment payload")
	}
	return errors.Wrap(writeOctetString(w, payload), "Failed to write octet string of payload")
}
