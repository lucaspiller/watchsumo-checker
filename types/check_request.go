package types

import (
	"net/url"
	"time"
)

// CheckRequest is a check request
type CheckRequest struct {
	// ID of monitoring or caller reference
	Ref string

	// HTTP method to use
	Method string

	// URL to check
	URL *url.URL

	// Additional request headers for request
	//Headers map[string][]string

	// Request body for request
	//Body string

	// Request timeout
	Timeout time.Duration

	// TODO
	// Assertions after request is complete
	// Assertions CheckAssertions

	// Request options
	Options CheckOptions
}

// CheckOptions check options
type CheckOptions struct {
	// If the request == HEAD fallback to GET if that fails
	GetFallback bool

	// Continue to make the request, even if the SSL certificate is not valid
	IgnoreTLSErrors bool

	// Follow redirects while performing the request
	FollowRedirects bool
}
