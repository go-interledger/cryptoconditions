package cryptoconditions

import "testing"

// standardFulfillmentTest performs standard tests on a fulfillment:
// - Tests if it generates the correct URI.
// - Tests if it can generates the correct condition.
// - Tests if the generated condition produces the correct URI.
func standardFulfillmentTest(t *testing.T, ff Fulfillment, correctFfUri, correctCondUri string) {
	t.Logf("Start standard fulfillment test for %v", correctFfUri)
	// Test if it generates the correct URI.
	ffUri, err := Uri(ff)
	if err != nil {
		t.Fatalf("Error generating ff uri: %v", err)
	}
	if ffUri != correctFfUri {
		t.Errorf("Generates incorrect URI: %v", ffUri)
	}

	// Test if it can generates the correct condition.
	ffCond := ff.Condition()
	correctCond, err := ParseConditionUri(correctCondUri)
	if err != nil {
		t.Fatalf("ERROR parsing condition URI: %v", err)
	}
	if !correctCond.Equals(ffCond) {
		t.Error("Condition does not equal expected condition.")
	}

	// Test if the generated condition produces the correct URI.
	ffCondUri, err := Uri(ffCond)
	if err != nil {
		t.Fatalf("Error generating cond uri: %v", err)
	}
	if ffCondUri != correctCondUri {
		t.Errorf("Generates incorrect condition URI: %v", ffCondUri)
	}
}
