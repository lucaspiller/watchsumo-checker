package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/lucaspiller/watchsumo-checker/metrics"
	"github.com/lucaspiller/watchsumo-checker/types"
)

const (
	maxTimeout   = 30 * time.Second
	maxRedirects = 5
)

var (
	errMaxRedirects = errors.New("Redirect limited exceeded")
)

// Checker engine
type Checker struct {
	Success bool

	Req *types.CheckRequest

	Res *types.CheckResult

	start time.Time
}

// Init initializers the checker
func Init(req *types.CheckRequest) *Checker {
	c := &Checker{}
	c.Req = req
	c.Res = &types.CheckResult{
		URL:    req.URL,
		Method: req.Method,
	}
	c.start = time.Now()

	return c
}

// Perform performs a check against a service.
func (c *Checker) Perform() bool {
	// Verify scheme is correct
	if c.Req.URL.Scheme != "http" && c.Req.URL.Scheme != "https" {
		message := fmt.Sprintf("Unsupported schema %s", c.Req.URL.Scheme)
		return c.handleFailure(message, types.UnsupportedSchema.ToString())
	}

	// Create transport
	// The transport is used for all requests for this check, so
	// if there are any Keep-Alives the connection will be reused.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()

	// Ignore TLS errors
	if c.Req.Options.IgnoreTLSErrors {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Enable/disable redirects
			if !c.Req.Options.FollowRedirects {
				return http.ErrUseLastResponse
			}

			// Check if redirect limit has been exceeded
			if len(via) > maxRedirects {
				return errMaxRedirects
			}

			return nil
		},
	}
	defer client.CloseIdleConnections()

	// Convert duration
	timeout := c.Req.Timeout
	if c.Req.Timeout > maxTimeout {
		timeout = maxTimeout
	}
	client.Timeout = timeout

	// Create request
	req, err := http.NewRequest(c.Req.Method, c.Req.URL.String(), nil)
	if err != nil {
		// Fallback to GET if a HEAD request fails
		if c.Req.Method == "HEAD" && c.Req.Options.GetFallback {
			return c.performGetFallback()
		}

		return c.handleError("Unable to create request", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36 (compatible; WatchSumo; +https://www.watchsumo.com)")
	req.Header.Set("Accept", "text/html,*/*;q=0.5")
	req.Header.Set("Accept-Charset", "utf-8,iso-8859-1;q=0.5")

	// Instrument the request, and extract timings at various points
	var t0, t1, t2, t3, t4, t5, t6, t7, t8 time.Time

	// Create trace
	trace := &httptrace.ClientTrace{
		DNSStart:             func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:              func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart:         func(_, _ string) { t2 = time.Now() },
		ConnectDone:          func(_, _ string, _ error) { t3 = time.Now() },
		TLSHandshakeStart:    func() { t4 = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { t5 = time.Now() },
		GotConn:              func(_ httptrace.GotConnInfo) { t6 = time.Now() },
		WroteHeaders:         func() { t7 = time.Now() },
		GotFirstResponseByte: func() { t8 = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		// Fallback to GET if a HEAD request fails
		if c.Req.Method == "HEAD" && c.Req.Options.GetFallback {
			return c.performGetFallback()
		}

		return c.handleError("Error making request", err)
	}

	// Read body
	respBody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		// Fallback to GET if a HEAD request fails
		if c.Req.Method == "HEAD" && c.Req.Options.GetFallback {
			return c.performGetFallback()
		}

		return c.handleError("Error reading response body", err)
	}

	t9 := time.Now() // after body has been fully read
	if t0.IsZero() {
		// we skipped the DNS lookup (it's an IP)
		t0 = t2
	}

	dns := t1.Sub(t0).Truncate(time.Millisecond)
	connecting := t3.Sub(t2).Truncate(time.Millisecond)

	// TLS handshake may have been skipped (existing TLS connection reused?)
	var tls time.Duration
	if !t4.IsZero() && !t5.IsZero() {
		tls = t5.Sub(t4).Truncate(time.Millisecond)
	}

	sending := t7.Sub(t6).Truncate(time.Millisecond)
	waiting := t8.Sub(t7).Truncate(time.Millisecond)
	receiving := t9.Sub(t8).Truncate(time.Millisecond)
	total := t9.Sub(t1).Truncate(time.Millisecond)

	c.Res.Timing = &types.RequestTiming{
		DNS:        &dns,
		Connecting: &connecting,
		TLS:        &tls,
		Sending:    &sending,
		Waiting:    &waiting,
		Receiving:  &receiving,
	}
	c.Res.Time = &total
	c.Res.Timestamp = &t9

	if resp.TLS != nil {
		c.Res.Certificate = certInfoFromTLSConnectionState(resp.TLS)
	}

	c.Res.Proto = resp.Proto
	c.Res.StatusText = resp.Status
	c.Res.StatusCode = resp.StatusCode
	c.Res.URL = resp.Request.URL // Update url if we were redirected
	c.Res.Headers = resp.Header
	c.Res.Body = string(respBody)

	// Check status code
	if resp.StatusCode != 200 && resp.StatusCode != 203 {
		// Fallback to GET if a HEAD request fails
		if c.Req.Method == "HEAD" && c.Req.Options.GetFallback {
			return c.performGetFallback()
		}

		return c.handleFailure("Unsuccessful status code", fmt.Sprintf("%d", resp.StatusCode))
	}

	c.Res.Status = types.StatusUp
	c.Success = true

	metrics.AddUp()
	metrics.AddCheckTime(total)

	return true
}

func (c *Checker) handleError(message string, err error) bool {
	now := time.Now()
	total := now.Sub(c.start)

	metrics.AddDown()
	metrics.AddCheckTime(total)

	c.Res.Time = &total
	c.Res.Timestamp = &now

	unwrappedError := c.unwrapError(err)
	c.Res.Certificate = certInfoFromCert(unwrappedError.Cert)
	c.Res.Error = unwrappedError.ToString()
	c.Res.Status = types.StatusDown
	c.Success = false

	return false
}

func (c *Checker) handleFailure(message, errorcode string) bool {
	now := time.Now()
	total := now.Sub(c.start)

	metrics.AddDown()
	metrics.AddCheckTime(total)

	c.Res.Time = &total
	c.Res.Timestamp = &now

	c.Res.Error = errorcode
	c.Res.Status = types.StatusDown
	c.Success = false

	return false
}

func (c *Checker) performGetFallback() bool {
	c.Req.Method = "GET"
	c.Res = &types.CheckResult{
		URL:    c.Req.URL,
		Method: c.Req.Method,
	}
	c.start = time.Now()

	return c.Perform()
}
