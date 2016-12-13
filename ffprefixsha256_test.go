package cryptoconditions

import "testing"

type testFfPrefixSha256Vector struct {
	sffUri, ffUri, condUri string
	prefix                 []byte
}

var testFfPrefixSha256Vectors = []testFfPrefixSha256Vector{
	{
		sffUri:  "cf:0:",
		ffUri:   "cf:1:AAAAAA",
		condUri: "cc:1:7:Yja3qFj7NS_VwwE7aJjPJos-uFCzStJlJLD4VsNy2XM:1",
		prefix:  []byte{},
	},
	{
		sffUri:  "cf:1:AAAAAA",
		ffUri:   "cf:1:AAABBAAAAAA",
		condUri: "cc:1:7:Mp5A0CLrJOMAUMe0-qFb-_5U2C0X-iuwwfvumOT0go8:2",
		prefix:  []byte{},
	},
	{
		sffUri:  "cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB",
		ffUri:   "cf:1:A2FiYwAEYHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1rsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQ",
		condUri: "cc:1:25:KHqL2K2uisoMhxznwl-6pai-ENDk2x9Wru6Ls63O5Vs:100",
		prefix:  []byte("abc"),
	},
}

func TestFfPrefixSha256Vectors(t *testing.T) {
	// vector-specific variables
	var vFf *FfPrefixSha256
	var vSff Fulfillment

	// Test vectors.
	for _, v := range testFfPrefixSha256Vectors {
		// initialize the vector variables
		var err error
		if vSff, err = ParseFulfillmentUri(v.sffUri); err != nil {
			t.Fatalf("ERROR in sub-fulfillment URI parsing for URI %s: %v", v.sffUri, err)
		}
		if ff, err := ParseFulfillmentUri(v.ffUri); err != nil {
			t.Fatalf("ERROR in fulfillment URI parsing: %v", err)
		} else {
			var ok bool
			vFf, ok = ff.(*FfPrefixSha256)
			if !ok {
				t.Fatalf("ERROR in casting ff: %v", err)
			}
		}

		// Perform the standard fulfillment tests.

		ff := NewFfPrefixSha256(v.prefix, vSff)
		standardFulfillmentTest(t, ff, v.ffUri, v.condUri)
		standardFulfillmentTest(t, vFf, v.ffUri, v.condUri)

		// Test if it generates the correct fulfillment URIs when unfulfilled.

		subCond, err := vSff.Condition()
		if err != nil {
			t.Fatalf("Failed to calculate condition from sub-fulfillment: %v", err)
		}
		ff = NewFfPrefixSha256Unfulfilled(v.prefix, subCond)
		_, err = Uri(ff)
		if err == nil {
			t.Error("Should be impossible to generate a URI for an unfulfilled fulfillment.")
		}
		cond, err := ff.Condition()
		if err != nil {
			t.Errorf("Failed to generate condition: %v", err)
		}
		condUri, err := Uri(cond)
		if err != nil {
			t.Errorf("Error generating cond uri: %v", err)
		}
		if condUri != v.condUri {
			t.Errorf("Generates incorrect condition URI: %v", condUri)
		}

		// Test if the fulfillment validates (with an empty message).

		err = vFf.Validate(nil)
		if err != nil {
			t.Errorf("Failed to validate fulfillment: %v", err)
		}
	}

}
