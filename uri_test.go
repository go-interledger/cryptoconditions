package cryptoconditions

import (
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURI_single(t *testing.T) {
	uri := "ni:///sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256"
	cond, err := ParseURI(uri)
	if assert.NoError(t, err) {
		assertEquivalentURIs(t, uri, cond.URI())
	}
}

func TestParseURI(t *testing.T) {
	// Simply decode a list of valid URI's without expecting an error.
	validURIs := []string{
		"ni:///sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256",
		"ni:///sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256",
		"ni:///sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536",
		"ni:///sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072",
		"ni:///sha-256;mDSHbc-wXLFnpcJJU-uljErImxrfV_KPL50JrxB-6PA?fpt=preimage-sha-256&cost=3",
		"ni:///sha-256;RR_hXxYpnUlZk_5pLbmJ5WpSMKkEdvdzkqPNMhPAcz8?fpt=prefix-sha-256&cost=132099&subtypes=ed25519-sha-256",
		"ni:///sha-256;F3NQrYVmxSi5LZtTgt8saNm6n5-kHUPb3Y5AsRjdlkE?fpt=prefix-sha-256&cost=133135&subtypes=ed25519-sha-256",
		"ni:///sha-256;tqz0CD5Di-Q1byX_ksKV6cjhurFBtGB7pIUR66Na78w?fpt=threshold-sha-256&cost=397315&subtypes=ed25519-sha-256,prefix-sha-256,rsa-sha-256",
		"ni:///sha-256;mgssY9-AaG5gINDKIcv-ZozOw9GvgnE_6um43UoPm7c?fpt=threshold-sha-256&cost=267264&subtypes=ed25519-sha-256,prefix-sha-256,preimage-sha-256,rsa-sha-256",
		"ni:///sha-256;jkM-9dPqoAorNKBcp8It05KXOhnxokMmjLUxEb3xyEQ?fpt=threshold-sha-256&cost=530438&subtypes=ed25519-sha-256,prefix-sha-256",
		"ni:///sha-256;DJljCiAambB0jSutsgXlypOWksaH0cSml-ObqLoevnE?fpt=threshold-sha-256&cost=399366&subtypes=ed25519-sha-256,prefix-sha-256,preimage-sha-256,rsa-sha-256",
		"ni:///sha-256;5P20ZSxvF6OLKr6aoAZAseGE_nqNDJcbXST37ab8aL8?fpt=threshold-sha-256&cost=2051&subtypes=preimage-sha-256",
		"ni:///sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536",
		"ni:///sha-256;TdLqf4Wz6suPGQWOg2CVXDLnTBJDkqH0RmBzlwnFOcM?fpt=rsa-sha-256&cost=262144",
		"ni:///sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072",
		"ni:///sha-256;CeORAEYocl6I-FV-lU-yoOrit8FRxH3zxK8i-MFpiPk?fpt=threshold-sha-256&cost=134304&subtypes=ed25519-sha-256,prefix-sha-256,preimage-sha-256",
		"ni:///sha-256;QkpwSUlSkme2IbPXkRnXKbI4LO2LKWw8Ao-pfTUPbQc?fpt=threshold-sha-256&cost=406738&subtypes=ed25519-sha-256,prefix-sha-256,preimage-sha-256",
	}

	for _, uri := range validURIs {
		t.Logf("Testing URI: %s", uri)
		cond, err := ParseURI(uri)
		if assert.NoError(t, err) {
			assertEquivalentURIs(t, uri, cond.URI())
		}
	}
}

// assertEquivalentURIs checks if the two URIs are equivalent.
func assertEquivalentURIs(t *testing.T, expected, actual string) {
	t.Logf("Comparing URIs:\nExpected: %s\nActual:   %s", expected, actual)
	u1, err := url.Parse(expected)
	require.NoError(t, err)
	u2, err := url.Parse(actual)
	require.NoError(t, err)

	assert.Equal(t, u1.Scheme, u2.Scheme)
	assert.Equal(t, u1.Host, u2.Host)
	assert.Equal(t, u1.Path, u2.Path)

	// We just go over the keys we know, the others we don't care about.
	q1 := u1.Query()
	q2 := u2.Query()
	queryValues := []string{"fpt", "cost"}
	for _, k := range queryValues {
		assert.Equal(t, q1.Get(k), q2.Get(k), k)
	}

	if q1.Get("subtypes") != "" || q2.Get("subtypes") != "" {
		st1 := strings.Split(q1.Get("subtypes"), ",")
		st2 := strings.Split(q2.Get("subtypes"), ",")
		sort.Strings(st1)
		sort.Strings(st2)
		assert.Equal(t, st1, st2)
	}
}
