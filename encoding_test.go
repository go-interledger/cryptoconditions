package cryptoconditions

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeFfPreimageSha256(t *testing.T) {
	f := &FfEd25519Sha256{
		PublicKey: []byte{0x61, 0x61, 0x61},
		Signature: []byte{0x61, 0x61, 0x61},
	}
	b, er := f.Encode()
	require.NoError(t, er)
	spew.Dump(b)

	//preimage := unbase64("YWFh")
	//t.Logf("Preimage hex: %x", preimage)
	//encoded := unhex("A0058003616161")
	//decoded, err := DecodeFulfillment(encoded)
	//require.NoError(t, err)
	//ff, ok := decoded.(*FfPreimageSha256)
	//require.True(t, ok)
	//
	//assert.Equal(t, preimage, ff.Preimage)

}

func TestDecodeFfPreimageSha256_Empty(t *testing.T) {
	preimage := []byte{}
	t.Logf("Preimage hex: %x", preimage)
	encoded := unhex("A0028000")
	decoded, err := DecodeFulfillment(encoded)
	require.NoError(t, err)
	ff, ok := decoded.(*FfPreimageSha256)
	require.True(t, ok)

	assert.Equal(t, preimage, ff.Preimage)

}
