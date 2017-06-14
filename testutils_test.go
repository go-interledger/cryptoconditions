package cryptoconditions

import (
	"encoding/hex"

	"github.com/kalaspuffar/base64url"
)

type fulfillmentWithContents interface {
	fingerprintContents() []byte
}

// unhex is used for testing and will panic when an invalid hex string is passed.
func unhex(hexString string) []byte {
	bts, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return bts
}

func unbase64(base64string string) []byte {
	bts, err := base64url.Decode(base64string)
	if err != nil {
		panic(err)
	}
	return bts
}
