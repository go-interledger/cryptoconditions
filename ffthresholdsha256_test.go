package cryptoconditions

import "testing"

type testFfThresholdSha256Vector struct {
	sffUris        []string
	threshold      uint32
	message        []byte
	ffUri, condUri string
}

var testFfThresholdSha256Vectors = []testFfThresholdSha256Vector{
	{
		[]string{
			"cf:0:",
		},
		1,
		nil,
		"cf:2:AQEBAQEBAwAAAAA",
		"cc:2:b:x07W1xU1_oBcV9zUheOzspx6Beq8vgy0vYgBVifNV1Q:10",
	},
	// Having the same subfulfillment appear twice is allowed, but note how it results in a
	// different condition URI, that is why this behavior is safe.
	{
		[]string{
			"cf:0:",
			"cf:0:",
		},
		2,
		nil,
		"cf:2:AQIBAgEBAwAAAAABAQMAAAAA",
		"cc:2:b:y93kXzLJ49Qdn3CeCe6Qtuzmdg9LhPHQIESn8H4ghE0:14",
	},
	{
		[]string{
			"cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB",
			"cf:0:AA",
		},
		1,
		nil,
		"cf:2:AQEBAgEBBAAAAQAAAQEAJwAEASAgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fUBYA",
		"cc:2:2b:qD3rZtABzeF5vPqkXN_AJYRStKoowpnivH1-9fQFjSo:146",
	},
	// The order of subconditions is irrelevant for both conditions and fulfillments
	{
		[]string{
			"cf:0:AA",
			"cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB",
		},
		1,
		nil,
		"cf:2:AQEBAgEBBAAAAQAAAQEAJwAEASAgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fUBYA",
		"cc:2:2b:qD3rZtABzeF5vPqkXN_AJYRStKoowpnivH1-9fQFjSo:146",
	},
	{
		[]string{
			"cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB",
			"cf:0:AA",
		},
		2,
		[]byte{"abc"},
		"cf:2:AQIBAgEBBAAAAQAAAQFjAARgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWABAA",
		"cc:2:2b:qmhBlTdYm8mukRoIJla3EH9vNorXqXSWaKnlMHzz5D4:111",
	},
}

//sffUris []string
//threshold uint32
//message []byte
//ffUri, condUri string

func TestFfThresholdSha256Vectors(t *testing.T) {
	var err error
	// vector-specific variables
	var vSffs []Fulfillment
	var vSffWeights []uint32
	var vFf FfThresholdSha256
	//var vCond *Condition

	// Test vectors.
	for _, v := range testFfThresholdSha256Vectors {
		// initialize the vector variables
		vSffs = make([]Fulfillment, len(v.sffUris))
		vSffWeights = make([]uint32, len(v.sffUris))
		for _, sffUri := range v.sffUris {
			sff, err := ParseFulfillmentUri(sffUri)
			if err != nil {
				t.Fatalf("ERROR parsing fulfillment URI: %v", err)
			}
			vSffs = append(vSffs, sff)
			vSffWeights = append(vSffWeights, 1)
		}
		//if vCond, err = ParseConditionUri(v.condUri); err != nil {
		//	t.Fatalf("ERROR in URI parsing: %v", err)
		//}
		if vFf, err = ParseFulfillmentUri(v.ffUri); err != nil {
			t.Fatalf("ERROR in URI parsing: %v", err)
		}

		// Perform the standard fulfillment tests.

		ff, err := NewFfThresholdSha256(v.threshold, vSffs, vSffWeights)
		if err != nil {
			t.Fatalf("Failed to construct Threshold-SHA-256 fulfillment: %v", err)
		}
		standardFulfillmentTest(t, ff, v.ffUri, v.condUri)
		standardFulfillmentTest(t, vFf, v.ffUri, v.condUri)

		// Test if the fulfillment validates (with an empty message).

		err = vFf.Validate(v.message)
		if err != nil {
			t.Errorf("Failed to validate fulfillment: %v", err)
		}
	}
}

func TestCalculateWorstCaseSffsLength(t *testing.T) {
	// every testVector consists of four slices:
	// - the first containes the threshold and the expected result
	// next we have three slices of equal length,
	// - the second the list of weights
	// - the
	var testVectors [][][]int
}
