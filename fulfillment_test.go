package cryptoconditions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// standardFulfillmentTest performs standard tests on a fulfillment:
// - Tests if it generates the correct URI.
// - Tests if it can generates the correct condition.
// - Tests if the generated condition produces the correct URI.
func standardFulfillmentTest(t *testing.T, ff Fulfillment, correctCondUri string) {
	// Test if it can generates the correct condition.
	ffCond := ff.Condition()
	correctCond, err := ParseURI(correctCondUri)
	require.NoError(t, err)
	assert.True(t, correctCond.Equals(ffCond))

	// Test if the generated condition produces the correct URI.
	ffCondUri := ffCond.URI()
	assert.Equal(t, correctCondUri, ffCondUri)
}
