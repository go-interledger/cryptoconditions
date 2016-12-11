package cryptoconditions

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestSerializeCondition(t *testing.T) {
	var err error
	var cond *Condition

	// Test parsing a valid condition.

	cond, err = DeserializeCondition(bytes.NewReader(unhex("0000010320e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550102")))
	if err != nil {
		t.Error("Failed to deserialize condition: ", err)
	}
	if cond.Fingerprint != unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Errorf("Condition has wrong fingerprint: %x", cond.Fingerprint)
	}

	// Test if attempting to pass invalid conditions fails.

	cond, err = DeserializeCondition(bytes.NewReader(unhex("00")))
	if err == nil {
		t.Error("Should reject a condition with less than two bytes")
	}
	cond, err = DeserializeCondition(bytes.NewReader(unhex("0000")))
	if err == nil {
		t.Error("Should reject a condition containing no fingerprint")
	}
	//TODO JS skips this test
	cond, err = DeserializeCondition(bytes.NewReader(unhex("000000010000")))
	if err == nil {
		t.Error("Should reject a condition containing extra bytes")
	}
	cond, err = DeserializeCondition(bytes.NewReader(unhex("000080")))
	if err == nil {
		t.Error("Should reject a condition with non-canonical zero byte length prefix")
	}
	cond, err = DeserializeCondition(bytes.NewReader(unhex("0000810100")))
	if err == nil {
		t.Error("Should reject a condition with non-canonical single byte length prefix")
	}
	cond, err = DeserializeCondition(bytes.NewReader(unhex("000082000100")))
	if err == nil {
		t.Error("Should reject a condition with non-canonical two byte length prefix")
	}
	cond, err = DeserializeCondition(bytes.NewReader(unhex("00008700000000000000")))
	if err == nil {
		t.Error("Should reject a condition with too large of a length prefix")
	}
}

func TestSerializeFulfillment(t *testing.T) {
	var err error
	var ff Fulfillment

	// Test parsing a valid fulfillment.

	// successfully parses the minimal fulfillment
	ff, err = DeserializeFulfillment(bytes.NewReader(unhex("000000")))
	if err != nil {
		t.Error("Failed to deserialize fulfillment: ", err)
	}
	pl, err := ff.Payload()
	if err != nil {
		t.Error("Error generating (empty) payload.")
	}
	if ff.Type() != CTPreimageSha256 {
		t.Errorf("Wrong ff type: %v", ff.Type())
	}
	if len(pl) != 0 {
		t.Errorf("Payload should be empty: %x", pl)
	}

	// successfully parses a basic fulfillment
	ff, err = DeserializeFulfillment(bytes.NewReader(unhex("00002050d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c")))
	if err != nil {
		t.Error("Failed to deserialize fulfillment: ", err)
	}
	if ff.Type() != CTPreimageSha256 {
		t.Errorf("Wrong ff type: %v", ff.Type())
	}
	pl, err = ff.Payload()
	if err != nil {
		t.Error("Error generating (empty) payload.")
	}
	if base64.StdEncoding.EncodeToString(pl) != "UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=" {
		t.Errorf("Incorrect payload: %v", base64.StdEncoding.EncodeToString(pl))
	}

	// successfully parses a fulfillment with base64url characters
	ff, err = DeserializeFulfillment(bytes.NewReader(unhex("000003faeffa")))
	if err != nil {
		t.Error("Failed to deserialize fulfillment: ", err)
	}
	if ff.Type() != CTPreimageSha256 {
		t.Errorf("Wrong ff type: %v", ff.Type())
	}
	pl, err = ff.Payload()
	if err != nil {
		t.Error("Error generating (empty) payload.")
	}
	if base64.StdEncoding.EncodeToString(pl) != "+u/6" {
		t.Errorf("Incorrect payload: %v", base64.StdEncoding.EncodeToString(pl))
	}

	// Test if attempting to pass invalid fulfillments fails.

	ff, err = DeserializeCondition(bytes.NewReader(unhex("00")))
	if err == nil {
		t.Error("Should reject a fulfillment with less than two bytes")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("0000")))
	if err == nil {
		t.Error("Should reject a fulfillment containing no payload")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("00000000")))
	if err == nil {
		t.Error("Should reject a fulfillment containing extra bytes")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("000080")))
	if err == nil {
		t.Error("Should reject a fulfillment with non-canonical zero byte length prefix")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("0000810100")))
	if err == nil {
		t.Error("Should reject a fulfillment with non-canonical single byte length prefix")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("000082000100")))
	if err == nil {
		t.Error("Should reject a fulfillment with non-canonical two byte length prefix")
	}
	ff, err = DeserializeCondition(bytes.NewReader(unhex("00008700000000000000")))
	if err == nil {
		t.Error("Should reject a fulfillment with too large of a length prefix")
	}
}
