package cryptoconditions

import (
	"crypto/sha512"

	"golang.org/x/crypto/ed25519"
)

// because the JS tests are defined using 32-byte seeds for private keys but the golang implementation of ed25519
// expects 64-byte keys, we will convert them instead of hard code the full keys
func ed25519KeyFromSeed(seed []byte) ed25519.PrivateKey {
	seedHash := sha512.Sum512(seed)
	return ed25519.PrivateKey(seedHash[:])
}

type testFfEd25519Sha256Vector struct {
	key     ed25519.PrivateKey
	message []byte
	condUri string
}

//var testFfEd25519Sha256Vectors = []testFfEd25519Sha256Vector{
//	{
//		ed25519KeyFromSeed(make([]byte, 32)),
//		nil,
//		"cc:4:20:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik:96",
//	},
//	{
//		ed25519KeyFromSeed(unhex(strings.Repeat("ff", 32))),
//		unhex("616263"),
//		"cc:4:20:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU:96",
//	},
//	{
//		ed25519KeyFromSeed(func() []byte { a := sha256.Sum256([]byte("example")); return a[:] }()),
//		unhex(strings.Repeat("21", 512)),
//		"cc:4:20:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVE:96",
//	},
//}
//
//func TestFfEd25519Sha256Vectors(t *testing.T) {
//	t.Log("Starting FfEd25519Sha256 vectors")
//	// vector-specific variables
//	var vFf *FfEd25519Sha256
//
//	// Test vectors.
//	for i, v := range testFfEd25519Sha256Vectors {
//		t.Logf("Vector index %v", i)
//		// initialize the vector variables
//		var err error
//		ff, err := ParseURI(v.ffUri)
//		require.NoError(t, err)
//		var ok bool
//		vFf, ok = ff.(*FfEd25519Sha256)
//		require.True(t, ok)
//
//		// Perform the standard fulfillment tests.
//
//		// construct signature
//		signature := ed25519.Sign(v.key, v.message)
//		ff, err = NewEd25519Sha256([]byte(v.key.Public().(ed25519.PublicKey)), signature)
//		require.NoError(t, err)
//		standardFulfillmentTest(t, ff, v.condUri)
//		standardFulfillmentTest(t, vFf, v.condUri)
//
//		// Test if the fulfillment validates (with an empty message).
//
//		err = vFf.Validate(nil, v.message)
//		require.NoError(t, err)
//	}
//
//}
