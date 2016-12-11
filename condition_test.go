package cryptoconditions

import "testing"

func TestCondition_Equals(t *testing.T) {
	cond1, err := ParseConditionUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	cond1copy, err := ParseConditionUri("cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	// different conditiontype
	cond2, err := ParseConditionUri("cc:1:2:37DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:1")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	// different features
	cond3, err := ParseConditionUri("cc:0:2:37DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	// different maxfulfillmentlength
	cond4, err := ParseConditionUri("cc:0:2:37DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:1")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}
	// different payload
	cond5, err := ParseConditionUri("cc:0:3:37DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0")
	if err != nil {
		t.Errorf("Parse error: %v", err)
	}

	// Test that cond1 is equal to cond1copy.
	if !cond1.Equals(cond1copy) {
		t.Error("Equal conditions are not recognized as such.")
	}
	if !cond1copy.Equals(cond1) {
		t.Error("Equal conditions are not recognized as such.")
	}

	// Test that cond1 is not equal to all other conds.

	for _, cond := range []*Condition{cond2, cond3, cond4, cond5} {
		if cond1.Equals(cond) {
			t.Errorf("Conditions %s and %s should not be equal.", cond1, cond)
		}
		if cond.Equals(cond1) {
			t.Errorf("Conditions %s and %s should not be equal.", cond1, cond)
		}
	}
}
