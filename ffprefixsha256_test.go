package cryptoconditions

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFfPrefixSha256_Encode(t *testing.T) {
	fpc := unhex("302E8000810100A227A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100")
	ffEncoding := unhex("A10B8000810100A204A0028000")
	condEncoding := unhex("A12A8020BB1AC5260C0141B7E54B26EC2330637C5597BF811951AC09E744AD20FF77E2878102040082020780")
	//condUri := unhex("ni:///sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256")

	innerFf := NewPreimageSha256([]byte{})
	ff := NewPrefixSha256([]byte{}, 0, innerFf)

	t.Logf("Preimage hash: %X", sha256.Sum256([]byte{}))
	t.Logf("Subcondition: A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100")
	t.Logf("Expected fpc: %X", fpc)
	ffFPC := ff.fingerprintContents()
	t.Logf("  Actual fpc: %X", ffFPC)
	assert.Equal(t, fpc, ffFPC)

	encodedFf, err := ff.Encode()
	require.NoError(t, err)
	assert.Equal(t, ffEncoding, encodedFf)

	cond := ff.Condition()
	encodedCond, err := cond.Encode()
	require.NoError(t, err)
	assert.Equal(t, 1024, cond.Cost())
	t.Logf("Condition fpt: %X", cond.Fingerprint())
	t.Logf("Expected cond: %X", condEncoding)
	t.Logf("  Actual cond: %X", encodedCond)
	assert.Equal(t, condEncoding, encodedCond)
}
