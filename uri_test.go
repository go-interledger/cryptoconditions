package cryptoconditions

import (
	"testing"

	"net/url"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertEquivalentURIs checks if the two URIs are equivalent.
func assertEquivalentURIs(t *testing.T, uri1, uri2 string) {
	//TODO implement
	u1, err := url.Parse(uri1)
	require.NoError(t, err)
	u2, err := url.Parse(uri2)
	require.NoError(t, err)

	assert.Equal(t, u1.Scheme, u2.Scheme)
	assert.Equal(t, u1.Host, u2.Host)
	assert.Equal(t, u1.Path, u2.Path)

	// We just go over the keys we know, the others we don't care about.
	q1 := u1.Query()
	q2 := u2.Query()
	queryValues := []string{"fpt", "cost", "subtypes"}
	for _, k := range queryValues {
		assert.Equal(t, q1.Get(k), q2.Get(k))
	}
}
