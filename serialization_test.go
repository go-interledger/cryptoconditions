package cryptoconditions

import (
	"bytes"
	"testing"
)

func TestSerializeCondition(t *testing.T) {

	// Test parsing a valid condition.

	cond, err := DeserializeCondition(bytes.NewReader(unhex("0000010320e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550102")))
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
