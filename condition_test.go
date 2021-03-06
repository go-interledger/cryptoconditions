package cryptoconditions

import (
	"crypto/sha256"
	"testing"

	"github.com/stevenroose/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionTypeSet_add(t *testing.T) {
	var set ConditionTypeSet

	assert.False(t, set.Has(CTPreimageSha256))
	assert.False(t, set.Has(CTEd25519Sha256))
	assert.Empty(t, set.AllTypes())
	asn1set := asn1.BitString(set)
	assert.Equal(t, 0, asn1set.At(int(CTPreimageSha256)))
	assert.Equal(t, 0, asn1set.At(int(CTPrefixSha256)))

	set2 := set
	set2.add(CTPreimageSha256)
	// test set has not chanced
	assert.False(t, set.Has(CTPreimageSha256))
	assert.False(t, set.Has(CTEd25519Sha256))
	assert.Empty(t, set.AllTypes())
	asn1set = asn1.BitString(set)
	assert.Equal(t, 0, asn1set.At(int(CTPreimageSha256)))
	assert.Equal(t, 0, asn1set.At(int(CTPrefixSha256)))
	// test set2
	asn1set2 := asn1.BitString(set2)
	assert.Equal(t, 1, asn1set2.At(int(CTPreimageSha256)))
	assert.Equal(t, 0, asn1set2.At(int(CTPrefixSha256)))
	assert.True(t, set2.Has(CTPreimageSha256))
	assert.False(t, set2.Has(CTEd25519Sha256))
	assert.Equal(t, 1, len(set2.AllTypes()))
}

func TestConditionTypeSet_add_loop(t *testing.T) {
	for i := 0; i < 65; i++ {
		set := ConditionTypeSet{}
		set.add(ConditionType(i))

		assert.Equal(t, i+1, set.BitLength)
		assert.True(t, set.Has(ConditionType(i)))
		assert.Equal(t, 1, asn1.BitString(set).At(i))
		assert.Equal(t, 1, len(set.AllTypes()))
	}
}

func TestConditionTypeSet_remove(t *testing.T) {
	var set ConditionTypeSet

	set.add(ConditionType(0))
	set.add(ConditionType(1))
	set.add(ConditionType(2))
	set.add(ConditionType(8))

	// verify setup
	assert.Equal(t, 9, set.BitLength)
	assert.Equal(t, 2, len(set.Bytes))
	assert.Equal(t, 4, len(set.AllTypes()))
	assert.True(t, set.Has(ConditionType(0)))
	assert.True(t, set.Has(ConditionType(1)))
	assert.True(t, set.Has(ConditionType(2)))
	assert.True(t, set.Has(ConditionType(8)))

	// remove bit that is already 0
	set.remove(ConditionType(3))
	assert.Equal(t, 9, set.BitLength)
	assert.Equal(t, 2, len(set.Bytes))
	assert.Equal(t, 4, len(set.AllTypes()))

	// remove bit 2
	set.remove(ConditionType(2))
	assert.False(t, set.Has(ConditionType(2)))
	assert.Equal(t, 9, set.BitLength)
	assert.Equal(t, 2, len(set.Bytes))
	assert.Equal(t, 3, len(set.AllTypes()))

	// remove bit 8
	set.remove(ConditionType(8))
	assert.False(t, set.Has(ConditionType(8)))
	// only 0 and 1 are still in it
	assert.Equal(t, 2, set.BitLength)
	assert.Equal(t, 1, len(set.Bytes))
	assert.Equal(t, 2, len(set.AllTypes()))
}

func TestConditionTypeSet_addAll(t *testing.T) {
	{
		var set1, set2 ConditionTypeSet

		set1.add(ConditionType(4))
		set2.add(ConditionType(15))
		set2.add(ConditionType(34))

		set1.addAll(set2)

		assert.True(t, set1.Has(ConditionType(4)))
		assert.True(t, set1.Has(ConditionType(15)))
		assert.True(t, set1.Has(ConditionType(34)))
		assert.Equal(t, 1, asn1.BitString(set1).At(4))
		assert.Equal(t, 1, asn1.BitString(set1).At(15))
		assert.Equal(t, 1, asn1.BitString(set1).At(34))
	}
	{
		var set1, set2 ConditionTypeSet

		set1.add(CTPreimageSha256)
		set2.add(CTPrefixSha256)

		set1.addAll(set2)

		assert.Equal(t, 2, len(set1.AllTypes()))
		assert.True(t, set1.Has(CTPreimageSha256))
		assert.True(t, set1.Has(CTPrefixSha256))
		assert.Equal(t, 1, asn1.BitString(set1).At(int(CTPreimageSha256)))
		assert.Equal(t, 1, asn1.BitString(set1).At(int(CTPrefixSha256)))
	}
}

func TestConditionTypeSet_addRelevant(t *testing.T) {
	{ // Condition
		subTypes := ConditionTypeSet{}
		subTypes.add(CTPreimageSha256)
		cond := Condition{
			conditionType: CTPrefixSha256,
			subTypes:      subTypes,
		}
		set := ConditionTypeSet{}
		set.addRelevant(cond)

		assert.Equal(t, 2, len(set.AllTypes()))
		assert.True(t, set.Has(CTPreimageSha256))
		assert.True(t, set.Has(CTPrefixSha256))
	}
	{ // Fulfillment
		ff := NewPreimageSha256(nil)
		set := ConditionTypeSet{}
		set.addRelevant(ff)

		assert.Equal(t, 1, len(set.AllTypes()))
		assert.True(t, set.Has(CTPreimageSha256))
	}
	{ // Compound condition fulfillment
		subFf := NewPreimageSha256(nil)
		ff := NewPrefixSha256(nil, 0, subFf)
		set := ConditionTypeSet{}
		set.addRelevant(ff)

		assert.Equal(t, 2, len(set.AllTypes()))
		assert.True(t, set.Has(CTPreimageSha256))
		assert.True(t, set.Has(CTPrefixSha256))
	}
}

func TestDecodeCondition_Preimage(t *testing.T) {
	encoding := unhex("A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100")
	uri := "ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0"
	fpc := []byte{}

	cond, err := DecodeCondition(encoding)
	require.NoError(t, err)

	assert.Equal(t, CTPreimageSha256, cond.Type())
	assert.Equal(t, 0, cond.Cost())
	fingerPrint := sha256.Sum256(fpc)
	assert.Equal(t, fingerPrint[:], cond.Fingerprint())
	enc, err := cond.Encode()
	require.NoError(t, err)
	assert.Equal(t, encoding, enc)
	assertEquivalentURIs(t, uri, cond.URI())
}

func TestDecodeCondition_Prefix(t *testing.T) {
	encoding := unhex("A12A8020BB1AC5260C0141B7E54B26EC2330637C5597BF811951AC09E744AD20FF77E2878102040082020780")
	uri := "ni:///sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256"
	fpc := unhex("302E8000810100A227A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100")
	ct := CTPrefixSha256
	cost := 1024

	cond, err := DecodeCondition(encoding)
	require.NoError(t, err)

	assert.Equal(t, ct, cond.Type())
	assert.Equal(t, cost, cond.Cost())
	fingerPrint := sha256.Sum256(fpc)
	assert.Equal(t, fingerPrint[:], cond.Fingerprint())
	enc, err := cond.Encode()
	require.NoError(t, err)
	assert.Equal(t, encoding, enc)
	assertEquivalentURIs(t, uri, cond.URI())
}

func TestDecodeCondition_RSA(t *testing.T) {
	encoding := unhex("A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000")
	uri := "ni:///sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536"
	fpc := unhex("3082010480820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B9")
	ct := CTRsaSha256
	cost := 65536

	cond, err := DecodeCondition(encoding)
	require.NoError(t, err)

	assert.Equal(t, ct, cond.Type())
	assert.Equal(t, cost, cond.Cost())
	fingerPrint := sha256.Sum256(fpc)
	assert.Equal(t, fingerPrint[:], cond.Fingerprint())
	enc, err := cond.Encode()
	require.NoError(t, err)
	assert.Equal(t, encoding, enc)
	assertEquivalentURIs(t, uri, cond.URI())
}
