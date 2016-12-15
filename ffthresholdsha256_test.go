package cryptoconditions

import (
	"math"
	"sort"
	"testing"
)

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
	// Having the same sub-fulfillment appear twice is allowed, but note how it results in a
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
	// The order of sub-conditions is irrelevant for both conditions and fulfillments
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
		[]byte("abc"),
		"cf:2:AQIBAgEBBAAAAQAAAQFjAARgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWABAA",
		"cc:2:2b:qmhBlTdYm8mukRoIJla3EH9vNorXqXSWaKnlMHzz5D4:111",
	},
}

//sffUris []string
//threshold uint32
//message []byte
//ffUri, condUri string

func TestFfThresholdSha256Vectors(t *testing.T) {
	t.Log("Start TestFfThresholdSha256Vectors")
	// vector-specific variables
	var vSffs []Fulfillment
	var vSffWeights []uint32
	var vFf *FfThresholdSha256
	//var vCond Condition

	// Test vectors.
	for i, v := range testFfThresholdSha256Vectors {
		t.Logf("Vector index %v", i)
		// initialize the vector variables
		vSffs = make([]Fulfillment, len(v.sffUris))
		vSffWeights = make([]uint32, len(v.sffUris))
		for i, sffUri := range v.sffUris {
			sff, err := ParseFulfillmentUri(sffUri)
			if err != nil {
				t.Fatalf("ERROR parsing fulfillment URI: %v", err)
			}
			vSffs[i] = sff
			vSffWeights[i] = 1
		}
		//if vCond, err = ParseConditionUri(v.condUri); err != nil {
		//	t.Fatalf("ERROR in URI parsing: %v", err)
		//}
		if ff, err := ParseFulfillmentUri(v.ffUri); err != nil {
			t.Fatalf("ERROR in URI parsing: %v", err)
		} else {
			var ok bool
			vFf, ok = ff.(*FfThresholdSha256)
			if !ok {
				t.Fatalf("ERROR in casting ff: %v", err)
			}
		}

		// Perform the standard fulfillment tests.
		ff := NewFfThresholdSha256(v.threshold, vSffs, vSffWeights)
		standardFulfillmentTest(t, ff, v.ffUri, v.condUri)
		standardFulfillmentTest(t, vFf, v.ffUri, v.condUri)

		// Test if the fulfillment validates (with an empty message).

		err := vFf.Validate(nil, v.message)
		if err != nil {
			t.Errorf("Failed to validate fulfillment: %v", err)
		}
	}
}

func TestCalculateWorstCaseSffsSize(t *testing.T) {
	t.Log("Starting TestCalculateWorstCaseSffsSize")
	// every testVector consists of four slices:
	// - the first containes the threshold and the expected result
	// next we have three slices of equal length,
	// - the second the list of weights
	// - the third is the list of (fulfillment) sizes
	// These values correspond to the information passed to calculateWorstCaseSffsLength
	var testVectors [][][]uint32
	testVectors = [][][]uint32{
		{
			{3, 3},
			{1, 4},
			{2, 3},
		},
		{
			{200, 9001},
			{115, 300},
			{52, 9001},
		},
		{
			{200, 9001},
			{115, 142, 300},
			{52, 18, 9001},
		},
		{
			{400, 1632},
			{162, 210, 143, 195, 43},
			{768, 514, 350, 382, 57},
		},
		{
			{100, math.MaxUint32},
			{15, 31, 12, 33, 8},
			{139, 134, 314, 133, 464},
		},
	}

	// Test the above vectors.
	for i, vector := range testVectors {
		t.Logf("Vector index %v", i)
		threshold := vector[0][0]
		expectedSize := vector[0][1]
		infos := make([]*weightedSubFulfillmentInfo, len(vector[1]))
		for i, weight := range vector[1] {
			infos[i] = &weightedSubFulfillmentInfo{
				weightedSubFulfillment: &weightedSubFulfillment{
					weight: weight,
				},
				size:     vector[2][i],
				omitSize: 0,
			}
		}

		// cast to weightedFulfillmentInfoSorter to sort
		sorter := weightedSubFulfillmentInfoSorter(infos)
		sort.Sort(sorter)

		calculated, err := calculateWorstCaseSffsSize(threshold, infos, 0)
		if expectedSize == math.MaxUint32 {
			// should not be able to calculate
			if err == nil {
				t.Errorf("Should not have been able to calculate size, but calculated %v", calculated)
			}
		} else if err != nil {
			t.Errorf("Was unable to calculate size (expected %v)", expectedSize)
		} else if err == nil && calculated != expectedSize {
			t.Errorf("Calculated worst size %v while we expected %v.", calculated, expectedSize)
		}
	}

}
