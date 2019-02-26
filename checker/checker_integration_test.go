package checker_test

import (
	"fmt"
	"net/url"
	"time"

	"testing"

	a "github.com/stretchr/testify/assert"

	"os"

	"github.com/lucaspiller/watchsumo-checker/checker"
	"github.com/lucaspiller/watchsumo-checker/types"
	log "github.com/sirupsen/logrus"
)

var httpBin string

func init() {
	val, ok := os.LookupEnv("HTTPBIN_URL")
	if !ok {
		httpBin = "http://localhost:8093"
	} else {
		httpBin = val
	}

	log.SetLevel(log.DebugLevel)
}

func buildCheck(rawurl string) *types.CheckRequest {
	url, err := url.Parse(rawurl)
	if err != nil || url.Host == "" {
		log.Fatalf("Invalid URL: %v", err)
	}

	return &types.CheckRequest{
		Ref:    "-1",
		Method: "HEAD",
		URL:    url,
		//Headers:        make(map[string][]string),
		//Body:           "",
		Timeout: 5 * time.Second,
		Options: types.CheckOptions{
			GetFallback:     false,
			IgnoreTLSErrors: false,
			FollowRedirects: true,
		},
	}
}

type test struct {
	url        string
	success    bool
	statusCode int
	error      string
}

type modifyRequest func(req *types.CheckRequest) *types.CheckRequest

func testTable(t *testing.T, tests []test, fn modifyRequest) {
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			fmt.Printf("%+v\n", tt)

			req := buildCheck(tt.url)
			if fn != nil {
				req = fn(req)
			}

			c := checker.Init(req)
			c.Perform()

			a.Equal(t, tt.success, c.Success)

			if tt.success {
				a.True(t, c.Res.Status == types.StatusUp)
			} else {
				a.True(t, c.Res.Status == types.StatusDown)
			}

			if tt.statusCode > 0 {
				a.Equal(t, tt.statusCode, c.Res.StatusCode)
			}

			a.Equal(t, tt.error, c.Res.Error)
		})
	}
}

func TestBasic(t *testing.T) {
	testTable(t, []test{
		{httpBin + "/status/200", true, 200, ""},
		{httpBin + "/status/203", true, 203, ""},
		{httpBin + "/status/201", false, 201, "201"},
		{httpBin + "/status/400", false, 400, "400"},
		{httpBin + "/status/500", false, 500, "500"},
	}, nil)
}

func TestRedirect(t *testing.T) {
	testTable(t, []test{
		{httpBin + "/redirect-to?url=" + httpBin + "&status_code=302", true, 200, ""},
		{httpBin + "/redirect-to?url=/&status_code=302", true, 200, ""},
		{httpBin + "/redirect-to?url=/&status_code=303", true, 200, ""},
		{httpBin + "/redirect-to?url=/&status_code=307", true, 200, ""},
		{httpBin + "/redirect-to?url=/&status_code=308", true, 200, ""},
	}, nil)
}

func TestRedirectLimit(t *testing.T) {
	testTable(t, []test{
		{httpBin + "/redirect/5?url=/", true, 200, ""},
		{httpBin + "/redirect/6?url=/", false, 0, types.MaxRedirects.ToString()},
	}, nil)
}

func Test302WithoutFollowRedirects(t *testing.T) {
	req := buildCheck(httpBin + "/redirect-to?url=" + httpBin)
	req.Options.FollowRedirects = false

	c := checker.Init(req)
	c.Perform()

	a.Equal(t, false, c.Success)
	a.True(t, c.Res.Status == types.StatusDown)
	a.Equal(t, "302", c.Res.Error)
	a.Equal(t, 302, c.Res.StatusCode)
}

func TestTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	lowerRequestTimeout := func(req *types.CheckRequest) *types.CheckRequest {
		req.Method = "GET"
		req.Timeout = 500 * time.Millisecond
		return req
	}

	testTable(t, []test{
		{httpBin + "/drip?delay=0&numbytes=100&duration=10", false, 0, types.Timeout.ToString()},
		{httpBin + "/delay/5", false, 0, types.Timeout.ToString()},
	}, lowerRequestTimeout)
}

func TestOtherErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	testTable(t, []test{
		{"http://non-existant-domain.foobar", false, 0, types.NxDomain.ToString()},
		{"http://localhost:9999", false, 0, types.ConnectionRefused.ToString()},
		{"http://172.17.0.5/", false, 0, types.HostUnreachable.ToString()},
		{"ftp://www.google.com", false, 0, types.UnsupportedSchema.ToString()},
	}, nil)
}

func TestBadSSLExpectFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	testTable(t, []test{
		{"https://expired.badssl.com", false, 0, types.CertExpired.ToString()},
		{"https://self-signed.badssl.com", false, 0, types.CertSelfSigned.ToString()},
		{"https://wrong.host.badssl.com", false, 0, types.CertWrongHost.ToString()},
		{"https://untrusted-root.badssl.com", false, 0, types.CertUntrustedAuthority.ToString()},
		{"https://incomplete-chain.badssl.com/", false, 0, types.CertIncompleteChain.ToString()},
		{"https://rc4.badssl.com", false, 0, types.TLSAlert.ToString()},
		{"https://rc4-md5.badssl.com", false, 0, types.TLSAlert.ToString()},
		{"https://null.badssl.com", false, 0, types.TLSAlert.ToString()},
		{"https://dh480.badssl.com", false, 0, types.TLSAlert.ToString()},
		{"https://dh512.badssl.com", false, 0, types.TLSAlert.ToString()},
		{"https://dh1024.badssl.com", false, 0, types.TLSAlert.ToString()},
	}, nil)
}
func TestBadSSLExpectSuccessUnsafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	// Known unsafe configurations that are still supported by browsers, so may be removed soon
	testTable(t, []test{
		{"https://3des.badssl.com", true, 200, ""},
		{"https://tls-v1-0.badssl.com:1010/", true, 200, ""},
		{"https://tls-v1-1.badssl.com:1011/", true, 200, ""},
	}, nil)
}

func TestBadSSLExpectSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	testTable(t, []test{
		{"https://badssl.com", true, 200, ""},
		{"https://sha256.badssl.com", true, 200, ""},
		{"https://sha384.badssl.com", true, 200, ""},
		{"https://sha512.badssl.com", true, 200, ""},
		{"https://1000-sans.badssl.com", true, 200, ""},
		{"https://ecc256.badssl.com", true, 200, ""},
		{"https://ecc384.badssl.com", true, 200, ""},
		{"https://rsa2048.badssl.com", true, 200, ""},
		{"https://rsa4096.badssl.com", true, 200, ""},
		{"https://tls-v1-2.badssl.com:1012/", true, 200, ""},
	}, nil)
}

func TestBadSSLIgnoreSSLFailureExpectSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	setIgnoreTLSErrors := func(req *types.CheckRequest) *types.CheckRequest {
		req.Options.IgnoreTLSErrors = true
		return req
	}

	testTable(t, []test{
		{"https://expired.badssl.com", true, 200, ""},
		{"https://self-signed.badssl.com", true, 200, ""},
		{"https://wrong.host.badssl.com", true, 200, ""},
		{"https://untrusted-root.badssl.com", true, 200, ""},
		{"https://incomplete-chain.badssl.com/", true, 200, ""},
	}, setIgnoreTLSErrors)
}

func TestSSLCert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	req1 := buildCheck("https://www.google.com/")
	c1 := checker.Init(req1)
	c1.Perform()

	a.Equal(t, true, c1.Success)
	a.Equal(t, "www.google.com", c1.Res.Certificate.Subject)

	req2 := buildCheck("https://wrong.host.badssl.com/")
	c2 := checker.Init(req2)
	c2.Perform()

	a.Equal(t, false, c2.Success)
	a.Equal(t, "*.badssl.com badssl.com", c2.Res.Certificate.Subject)
}

func TestGetFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	req := buildCheck("https://outlook.live.com/owa/")

	c1 := checker.Init(req)
	c1.Perform()

	a.Equal(t, false, c1.Success)
	a.True(t, c1.Res.Status == types.StatusDown)
	a.Equal(t, 440, c1.Res.StatusCode)

	req.Options.GetFallback = true

	c2 := checker.Init(req)
	c2.Perform()

	a.Equal(t, true, c2.Success)
	a.True(t, c2.Res.Status == types.StatusUp)
	a.Equal(t, 200, c2.Res.StatusCode)
}
