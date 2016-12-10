package cryptoconditions

// Features is a bitflag type representing feature suites.
type Features uint8

const (
	FSha256 = 1 << iota

	FPreimage

	FPrefix

	FThreshold

	FRsaPss

	FEd25519
)
