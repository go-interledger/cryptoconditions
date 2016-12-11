package cryptoconditions

import "io"

// SerializeCondition writes the condition to the writer.
func SerializeCondition(w io.Writer, c *Condition) error {
	// write condition type
	if err := writeConditionType(w, c.Type); err != nil {
		return err
	}
	// write features
	writeFeatures(w, c.Features)
	// write fingerprint
	if err := writeOctetString(w, c.Fingerprint); err != nil {
		return err
	}
	// write max fulfillment length
	return writeVarUInt(w, int(c.MaxFulfillmentLength))
}

// DeserializeCondition reads a condition from the reader.
func DeserializeCondition(r io.Reader) (*Condition, error) {
	var err error
	c := new(Condition)
	if c.Type, err = readConditionType(r); err != nil {
		return nil, err
	}
	if c.Features, err = readFeatures(r); err != nil {
		return nil, err
	}
	if c.Fingerprint, err = readOctetString(r); err != nil {
		return nil, err
	}
	if mff, err := readVarUInt(r); err != nil {
		return nil, err
	} else {
		c.MaxFulfillmentLength = uint32(mff)
	}
	return c, nil
}

// SerializeFulfillment writes a fulfillment to the writer.
func SerializeFulfillment(w io.Writer, ff Fulfillment) error {
	if err := writeConditionType(w, ff.Type()); err != nil {
		return err
	}
	payload, err := ff.Payload()
	if err != nil {
		return err
	}
	return writeOctetString(w, payload)
}

// SerializeFulfillment reads a fulfillment from the reader.
func DeserializeFulfillment(r io.Reader) (Fulfillment, error) {
	// read condition type and payload
	conditionType, err := readConditionType(r)
	if err != nil {
		return nil, err
	}
	payload, err := readOctetString(r)
	if err != nil {
		return nil, err
	}

	ff, err := newFulfillmentByType(conditionType)
	if err != nil {
		return nil, err
	}
	if err := ff.ParsePayload(payload); err != nil {
		return nil, err
	}

	return ff, nil
}
