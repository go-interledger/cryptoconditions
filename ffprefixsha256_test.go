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
		prefix:  []byte{"abc"},
	},
}

func TestFfPrefixSha256Vectors(t *testing.T) {
	var err error
	// vector-specific variables
	var vFf FfPrefixSha256
	var vSff Fulfillment

	// Test vectors.
	for _, v := range testFfPrefixSha256Vectors {
		// initialize the vector variables
		if vSff, err = ParseFulfillmentUri(v.sffUri); err != nil {
			t.Errorf("ERROR in URI parsing: %v", err)
		}
		if vFf, err = ParseFulfillmentUri(v.ffUri); err != nil {
			t.Errorf("ERROR in URI parsing: %v", err)
		}

		// Test if it generates the correct fulfillment URIs.

		ff := NewFfPrefixSha256(v.prefix, vSff)
		uri, err := Uri(ff)
		if err != nil {
			t.Errorf("Error generating ff uri: %v", err)
		}
		if uri != v.ffUri {
			t.Errorf("Generates incorrect URI: %v", uri)
		}
		cond, err := ff.Condition()
		if err != nil {
			t.Errorf("Failed to generate condition: %v", err)
		}
		conduri, err := Uri(cond)
		if err != nil {
			t.Errorf("Error generating cond uri: %v", err)
		}
		if conduri != v.condUri {
			t.Errorf("Generates incorrect condition URI: %v", conduri)
		}

		// Test if it generates the correct fulfillment URIs when unfulfilled.

		subCond, err := vSff.Condition()
		if err != nil {
			t.Errorf("Failed to calculate condition from subfulfillment: %v", err)
		}
		ff = NewFfPrefixSha256Unfulfilled(v.prefix, subCond)
		uri, err = Uri(ff)
		if err == nil {
			t.Error("Should be impossible to generate a URI for an unfulfilled fulfillment.")
		}
		cond, err = ff.Condition()
		if err != nil {
			t.Errorf("Failed to generate condition: %v", err)
		}
		conduri, err = Uri(cond)
		if err != nil {
			t.Errorf("Error generating cond uri: %v", err)
		}
		if conduri != v.condUri {
			t.Errorf("Generates incorrect condition URI: %v", conduri)
		}

		// Test if the fulfillment validates (with an empty message).

		err = vFf.Validate(nil)
		if err != nil {
			t.Errorf("Failed to validate fulfillment: %v", err)
		}
	}

}
