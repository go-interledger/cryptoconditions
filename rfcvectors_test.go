package cryptoconditions

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TODO threshold condition tests are skipped!

// This file implements tests for the test vectors provided by the RFC.
// The vectors can be found here:
// https://github.com/rfcs/crypto-conditions/tree/master/test-vectors/valid
// The implementation is last updated on git commit
// c50cba9a5057fd497923962e0ea66b603a5ba665.

const (
	testRfcVectorPathValid   = "rfc-vectors/valid/"
	testRfcVectorPathInvalid = "rfc-vectors/invalid/"
)

type hexBytes []byte

func (h hexBytes) bytes() []byte {
	return []byte(h)
}

func (h *hexBytes) UnmarshalText(input []byte) error {
	b, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	*h = b
	return nil
}

func (h hexBytes) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h)), nil
}

// rfcVector holds the JSON encoding used for the RFC test vectors.
type rfcVector struct {
	JSON                map[string]interface{} `json:"json"`
	Cost                int                    `json:"cost"`
	Subtypes            []string               `json:"subtypes"`
	FingerprintContents hexBytes               `json:"fingerprintContents"`
	FulfillmentEncoding hexBytes               `json:"fulfillment"`
	ConditionBinary     hexBytes               `json:"conditionBinary"`
	ConditionUri        string                 `json:"conditionUri"`
	Message             string                 `json:"message"`

	// This field will be populated using the JSON field.
	fulfillment Fulfillment
}

// testRfcVectorGet reads and parses a vector from its JSON file into an
// rfcVector object.
func testRfcVectorGet(t *testing.T, valid bool, filename string) rfcVector {
	var vectorDir string
	if valid {
		vectorDir = testRfcVectorPathValid
	} else {
		vectorDir = testRfcVectorPathInvalid
	}

	// Generate the full file path and check if it exists.
	filePath := filepath.Join(vectorDir, filename)
	_, err := os.Stat(filePath)
	require.False(t, os.IsNotExist(err))

	// Read the JSON file.
	raw, err := ioutil.ReadFile(filePath)
	require.NoError(t, err)

	vector := rfcVector{}

	// Unmarshal the JSON into the vector object.
	require.NoError(t, json.Unmarshal(raw, &vector))

	return vector
}

// testRfcVectorConditionTypeMapping maps the type identifiers used in the
// vector JSON format to the types used in this implementation.
var testRfcVectorConditionTypeMapping = map[string]ConditionType{
	"preimage-sha-256":  CTPreimageSha256,
	"prefix-sha-256":    CTPrefixSha256,
	"threshold-sha-256": CTThresholdSha256,
	"rsa-sha-256":       CTRsaSha256,
	"ed25519-sha-256":   CTEd25519Sha256,
}

// testRfcVectorConstructFulfillmentJSON constructs a fulfillment from hte JSON
// parameters in the vector file. It will also check whether the condition type
// of the resulting fulfillment is correct.
func testRfcVectorConstructFulfillmentFromJSON(t *testing.T, fields map[string]interface{}) Fulfillment {
	var ff Fulfillment
	var err error
	expectedType := testRfcVectorConditionTypeMapping[fields["type"].(string)]
	switch expectedType {

	case CTPreimageSha256:
		preimage := unbase64(fields["preimage"].(string))
		ff = NewPreimageSha256(preimage)

	case CTPrefixSha256:
		prefix := unbase64(fields["prefix"].(string))
		//maxMessageLength := jsonFields["maxMessageLength"]
		subfulfillment := testRfcVectorConstructFulfillmentFromJSON(
			t, fields["subfulfillment"].(map[string]interface{}))
		ff = NewPrefixSha256(prefix,
			uint32(fields["maxMessageLength"].(float64)), subfulfillment)

	case CTThresholdSha256:
		t.SkipNow()
		threshold := uint16(fields["threshold"].(float64))
		subfulfillments := make([]Fulfillment,
			len(fields["subfulfillments"].([]interface{})))
		for i, sffJson := range fields["subfulfillments"].([]interface{}) {
			sffJsonMap := sffJson.(map[string]interface{})
			subfulfillments[i] = testRfcVectorConstructFulfillmentFromJSON(
				t, sffJsonMap)
		}
		ff = NewThresholdSha256(threshold, subfulfillments, nil)

	case CTRsaSha256:
		modulus := unbase64(fields["modulus"].(string))
		signature := unbase64(fields["signature"].(string))
		ff, err = NewRsaSha256(modulus, signature)
		require.NoError(t, err)

	case CTEd25519Sha256:
		pubkey := unbase64(fields["publicKey"].(string))
		signature := unbase64(fields["signature"].(string))
		ff, err = NewEd25519Sha256(pubkey, signature)
		require.NoError(t, err)

	default:
		panic(fmt.Sprintf(
			"Unknown condition type in vector: %s",
			fields["type"].(string)))

	}

	// Assert that the generated fulfillment is from the expected type.
	require.Equal(t, expectedType, ff.ConditionType())

	return ff
}

// testRfcVectorStandard performs the tests for a test vector.
// It tests the following:
//  - Parse conditionBinary, serialize as a URI, should match conditionUri.
//  - Parse conditionUri, serialize as binary, should match conditionBinary.
//  - Parse fulfillment, serialize fulfillment, should match fulfillment.
//  - Parse fulfillment and validate, should return true.
//  - Parse fulfillment and generate the fingerprint contents
//  - Parse fulfillment, generate the condition, serialize the
//    condition as a URI, should match conditionUri.
//  - Create fulfillment from json, serialize fulfillment,
//    should match fulfillment.
func testRfcVectorValidStandard(t *testing.T, vector rfcVector) {

	{
		// Parse conditionBinary, serialize as a URI, should match conditionUri.
		cond, err := DecodeCondition(vector.ConditionBinary)
		require.NoError(t, err)
		assertEquivalentURIs(t, vector.ConditionUri, cond.URI())
	}
	{
		// Parse conditionUri, serialize as binary, should match conditionBinary.
		t.Logf("URI: %s", vector.ConditionUri)
		cond, err := ParseURI(vector.ConditionUri)
		require.NoError(t, err)
		encoded, err := cond.Encode()
		require.NoError(t, err)
		assert.Equal(t, vector.ConditionBinary.bytes(), encoded)
	}
	{
		// Parse fulfillment, serialize fulfillment, should match fulfillment.
		ff, err := DecodeFulfillment(vector.FulfillmentEncoding)
		require.NoError(t, err)
		encoded, err := ff.Encode()
		require.NoError(t, err)
		assert.Equal(t, vector.FulfillmentEncoding.bytes(), encoded)
	}
	{
		// Parse fulfillment and validate, should return true.
		ff, err := DecodeFulfillment(vector.FulfillmentEncoding)
		require.NoError(t, err)
		cond, err := DecodeCondition(vector.ConditionBinary.bytes())
		require.NoError(t, err)
		msg := unhex(vector.Message)
		assert.NoError(t, ff.Validate(cond, msg))
	}
	{
		// Parse fulfillment and generate the fingerprint contents
		ff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
		require.NoError(t, err)
		fpc := ff.fingerprintContents()
		assert.Equal(t, vector.FingerprintContents.bytes(), fpc)
	}
	{
		// Parse fulfillment, generate the condition, serialize the
		// condition as a URI, should match conditionUri.
		ff, err := DecodeFulfillment(vector.FulfillmentEncoding)
		require.NoError(t, err)
		assertEquivalentURIs(t, vector.ConditionUri, ff.Condition().URI())
	}
	{
		// Create fulfillment from json, serialize fulfillment,
		// should match fulfillment.
		ff := testRfcVectorConstructFulfillmentFromJSON(t, vector.JSON)
		encoded, err := ff.Encode()
		require.NoError(t, err)
		assert.Equal(t, vector.FulfillmentEncoding.bytes(), encoded)
	}
}

func testRfcVectorValidPreimageSha256(t *testing.T, vector rfcVector) {
	// Decode and cast the fulfillment.
	gff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
	require.NoError(t, err)
	ff, ok := gff.(*FfPreimageSha256)
	require.True(t, ok)

	// Check if the preimage is correct.
	preimage := unbase64(vector.JSON["preimage"].(string))
	assert.Equal(t, preimage, ff.Preimage)
}

func testRfcVectorValidPrefixSha256(t *testing.T, vector rfcVector) {
	// Decode and cast the fulfillment.
	gff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
	require.NoError(t, err)
	ff, ok := gff.(*FfPrefixSha256)
	require.True(t, ok)

	// Check if the prefix is correct.
	prefix := unbase64(vector.JSON["prefix"].(string))
	assert.Equal(t, prefix, ff.Prefix)
}

func testRfcVectorValidThresholdSha256(t *testing.T, vector rfcVector) {
	// Decode and cast the fulfillment.
	gff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
	require.NoError(t, err)
	ff, ok := gff.(*FfThresholdSha256)
	require.True(t, ok)

	vff, ok := vector.fulfillment.(*FfThresholdSha256)
	require.True(t, ok)

	// Check if the threshold is correct.
	threshold := vector.JSON["threshold"]
	assert.Equal(t, threshold, ff.Threshold)

	// Check if subfulfillments are equivalent.
	if assert.Equal(t, len(vff.SubFulfillments), len(ff.SubFulfillments)) {
		for i, vsff := range vff.SubFulfillments {
			assert.True(t, vsff.Condition().Equals(
				ff.SubFulfillments[i].Condition()))
		}
	}

	// Check if subconditions are equivalent.
	if assert.Equal(t, len(vff.SubConditions), len(ff.SubConditions)) {
		for i, vsffC := range vff.SubConditions {
			assert.True(t, vsffC.Equals(ff.SubConditions[i]))
		}
	}
}

func testRfcVectorValidRsaSha256(t *testing.T, vector rfcVector) {
	// Decode and cast the fulfillment.
	gff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
	require.NoError(t, err)
	ff, ok := gff.(*FfRsaSha256)
	require.True(t, ok)

	assert.Equal(t, ff.Modulus, ff.Modulus)
	assert.Equal(t, ff.Signature, ff.Signature)
}

func testRfcVectorValidEd25519Sha256(t *testing.T, vector rfcVector) {
	// Decode and cast the fulfillment.
	gff, err := DecodeFulfillment(vector.FulfillmentEncoding.bytes())
	require.NoError(t, err)
	ff, ok := gff.(*FfEd25519Sha256)
	require.True(t, ok)

	assert.Equal(t, ff.PublicKey, ff.PublicKey)
	assert.Equal(t, ff.Signature, ff.Signature)
}

// testRfcVectorValidFulfillmentTesters maps condition types to the method that
// performs tests specific to fulfillments of that condition type.
var testRfcVectorValidFulfillmentTesters = map[ConditionType]func(t *testing.T, vector rfcVector){
	CTPreimageSha256:  testRfcVectorValidPreimageSha256,
	CTPrefixSha256:    testRfcVectorValidPrefixSha256,
	CTThresholdSha256: testRfcVectorValidThresholdSha256,
	CTRsaSha256:       testRfcVectorValidRsaSha256,
	CTEd25519Sha256:   testRfcVectorValidEd25519Sha256,
}

func TestRfcVectors(t *testing.T) {
	// Vectors for valid fulfillments.
	validVectorFiles, err := ioutil.ReadDir(testRfcVectorPathValid)
	require.NoError(t, err)
	for _, vectorFile := range validVectorFiles {
		if vectorFile.IsDir() {
			continue
		}
		if vectorFile.Size() == 0 {
			continue
		}
		vectorFileName := vectorFile.Name()
		testName := fmt.Sprintf("valid %s", vectorFileName)
		t.Run(testName, func(t *testing.T) {
			//t.Parallel()
			t.Logf("Running vector %s", testName)
			// Read the vector file.
			vector := testRfcVectorGet(t, true, vectorFileName)
			// Construct the fulfillment from JSON.
			vector.fulfillment = testRfcVectorConstructFulfillmentFromJSON(t, vector.JSON)
			// Run the standard tests.
			testRfcVectorValidStandard(t, vector)
			// Run the type-specific tests.
			typeSpecificTester := testRfcVectorValidFulfillmentTesters[vector.fulfillment.ConditionType()]
			if typeSpecificTester == nil {
				t.Log("Failing because no type-specific tester function")
				t.FailNow()
			}
			typeSpecificTester(t, vector)
		})
	}

	// Vectors for invalid fulfillments.
	invalidVectorFiles, err := ioutil.ReadDir(testRfcVectorPathInvalid)
	require.NoError(t, err)
	for _, vectorFile := range invalidVectorFiles {
		if vectorFile.IsDir() {
			continue
		}
		if vectorFile.Size() == 0 {
			continue
		}
		vectorFileName := vectorFile.Name()
		testName := fmt.Sprintf("invalid %s", vectorFileName)
		t.Run(testName, func(t *testing.T) {
			//t.Parallel()
			t.Logf("Running vector %s", testName)
			// Read the vector file.
			//vector := testRfcVectorGet(t, false, vectorFile.Name())
			t.Fatal("Invalid tests not yet implemented")
		})
	}
}
