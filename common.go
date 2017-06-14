package cryptoconditions

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
