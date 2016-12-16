package cryptoconditions

import (
	"encoding/hex"
)

// max returns the highest of both integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the lowest of both integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// unhex is used for testing and will panic when an invalid hex string is passed.
func unhex(hexString string) []byte {
	bts, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return bts
}
