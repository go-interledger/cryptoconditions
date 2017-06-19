package cryptoconditions

import (
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
)

func TestFfThresholdSha256_Encode(t *testing.T) {
	t.SkipNow() //TODO threshold conditions are not yet supported!

	vectorFpt := "302C800101A127A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100"
	vectorFfEncoding := "A208A004A0028000A100"
	vectorConditionEncoding := "A22A8020B4B84136DF48A71D73F4985C04C6767A778ECB65BA7023B4506823BEEE7631B98102040082020780"
	vectorConditionURI := "ni:///sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256"

	subFf := NewPreimageSha256([]byte{})
	ff := NewThresholdSha256(1, []Fulfillment{subFf}, nil)

	encodedFf, err := ff.Encode()
	require.NoError(t, err)
	assert.Equal(t, vectorFfEncoding, encodedFf)

	t.FailNow()

	assert.Equal(t, vectorFpt, ff.fingerprint())

	encodedCondition, err := ff.Condition().Encode()
	require.NoError(t, err)
	assert.Equal(t, vectorConditionEncoding, encodedCondition)

	assert.Equal(t, vectorConditionURI, ff.Condition().URI())
}
