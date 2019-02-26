package types

// CheckStatus is the status of a check
type CheckStatus string

const (
	// StatusUp site is up
	StatusUp CheckStatus = "up"

	// StatusDown site is down
	StatusDown CheckStatus = "down"

	// StatusUnknown site status is unknown
	StatusUnknown CheckStatus = "unknown"
)
