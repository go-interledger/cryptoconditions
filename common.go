package cryptoconditions

import "encoding/hex"

// min returns the lowest of both integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the highest of both integers.
func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// unhex is used for testing and will panic when an invalid hex string is passed.
func unhex(hexString string) []byte {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	return bytes
}

// writeCounter implements io.Writer but only counts the number of bytes that are passed to the
// `Write` method.
type writeCounter struct {
	counter int
}

func (w *writeCounter) Write(bytes []byte) (int, error) {
	ln := len(bytes)
	w.counter += ln
	return ln, nil
}

func (w *writeCounter) Skip(n int) {
	w.counter += n
}

func (w *writeCounter) Counter() int {
	return w.counter
}
