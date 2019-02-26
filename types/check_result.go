package types

import (
	"net/url"
	"time"
)

// CheckResult is the result of a check
type CheckResult struct {
	// Overall check result
	Status CheckStatus

	// HTTP that was used
	Method string

	// URL that was checked
	URL *url.URL

	// HTTP status code received
	StatusCode int

	// protocol, e.g. HTTP/1.1
	Proto string

	// status text, e.g. 200 OK
	StatusText string

	// Response headers received
	Headers map[string][]string

	// Response body received
	Body string

	// Overall time for the request
	Time *time.Duration

	// Information about the SSL certificate
	Certificate *CertInfo

	// Detailed timings of the request
	Timing *RequestTiming

	// TODO
	// Results of assertions
	// Assertions AssertionResult

	// Error description
	Error string

	// Time the check was completed
	Timestamp *time.Time
}

// Success returns whether the check was successful
func (r *CheckResult) Success() bool {
	return r.Status == StatusUp
}

// ResponseHeader response headers
type ResponseHeader struct {
	// Key of header
	Key string

	// Value of header
	Value string
}

// RequestTiming contains timings of each part of the request
type RequestTiming struct {
	DNS        *time.Duration
	Connecting *time.Duration
	TLS        *time.Duration
	Sending    *time.Duration
	Waiting    *time.Duration
	Receiving  *time.Duration
}

// CertInfo contains information about the TLS certificate used
type CertInfo struct {
	SerialString      string
	Serial            []byte
	Algorithm         int
	ValidFrom         time.Time
	ValidTo           time.Time
	Subject           string
	Issuer            string
	FingerprintSHA256 []byte
}
