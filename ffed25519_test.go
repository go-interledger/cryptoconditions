package cryptoconditions

import (
	"crypto/sha256"
	"strings"
	"testing"

	"crypto/sha512"

	"golang.org/x/crypto/ed25519"
)

// because the JS tests are defined using 32-byte seeds for private keys but the golang implementation of ed25519
// expects 64-byte keys, we will convert them instead of hard code the full keys
func ed25519KeyFromSeed(seed []byte) ed25519.PrivateKey {
	seedHash := sha512.Sum512(seed)
	return ed25519.PrivateKey(seedHash[:])
}

type testFfEd25519Vector struct {
	key            ed25519.PrivateKey
	message        []byte
	ffUri, condUri string
}

var testFfEd25519Vectors = []testFfEd25519Vector{
	{
		ed25519KeyFromSeed(make([]byte, 32)),
		nil,
		"cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD",
		"cc:4:20:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik:96",
	},
	{
		ed25519KeyFromSeed(unhex(strings.Repeat("ff", 32))),
		unhex("616263"),
		"cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB",
		"cc:4:20:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU:96",
	},
	{
		ed25519KeyFromSeed(func() []byte { a := sha256.Sum256([]byte("example")); return a[:] }()),
		unhex(strings.Repeat("21", 512)),
		"cf:4:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVGfTbzglso5Uo3i2O2WVP6abH1dz5k0H5DLylizTeL5UC0VSptUN4VCkhtbwx3B00pCeWNy1H78rq6OTXzok-EH",
		"cc:4:20:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVE:96",
	},
}

func TestFfEd25519_Validate(t *testing.T) {

	// Should accept a valid signature.

	ff, err := ParseFulfillmentUri("cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD")
	if err != nil {
		t.Fatalf("ERROR parsing fulfillment URI: %v", err)
	}

	if err := ff.Validate(nil); err != nil {
		t.Errorf("Could not validate valid fulfillment: %v", err)
	}

	// Should throw if the signature is invalid.

	ff, err = ParseFulfillmentUri("cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD")
	if err != nil {
		t.Fatalf("ERROR parsing fulfillment URI: %v", err)
	}
	// invalidate the signature
	ff.(*FfEd25519).signature[4] |= 0x40

	if ff.Validate(nil) == nil {
		t.Error("Should not be able to validate invalid fulfillment")
	}
}

func TestFfEd25519Vectors(t *testing.T) {
	t.Log("Starting FfEd25519 vectors")
	// vector-specific variables
	var vFf *FfEd25519

	// Test vectors.
	for i, v := range testFfEd25519Vectors {
		t.Logf("Vector index %v", i)
		// initialize the vector variables
		var err error
		if ff, err := ParseFulfillmentUri(v.ffUri); err != nil {
			t.Fatalf("ERROR in fulfillment URI parsing: %v", err)
		} else {
			var ok bool
			vFf, ok = ff.(*FfEd25519)
			if !ok {
				t.Fatalf("ERROR in casting ff: %v", err)
			}
		}

		// Perform the standard fulfillment tests.

		// construct signature
		signature := ed25519.Sign(v.key, v.message)
		ff := NewFfEd25519(v.key.Public().(ed25519.PublicKey), signature)
		standardFulfillmentTest(t, ff, v.ffUri, v.condUri)
		standardFulfillmentTest(t, vFf, v.ffUri, v.condUri)

		// Test if the fulfillment validates (with an empty message).

		err = vFf.Validate(v.message)
		if err != nil {
			t.Errorf("Failed to validate fulfillment with message \"%x\": %v", v.message, err)
		}
	}

}
