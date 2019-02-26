package types

// CheckError is the error while performing the check
type CheckError string

const (
	// UnknownError means something went wrong
	UnknownError CheckError = "unknown_error"

	// NxDomain means the domain wasn't found
	NxDomain CheckError = "nxdomain"

	// DNSError means there was an error performing the DNS lookup
	DNSError CheckError = "dns_error"

	// Timeout while performing check
	Timeout CheckError = "timeout"

	// MaxRedirects limit exceeded
	MaxRedirects CheckError = "max_redirects"

	// HostUnreachable error connecting to host
	HostUnreachable CheckError = "ehostunreach"

	// ConnectionRefused connection refused
	ConnectionRefused CheckError = "econnrefused"

	// Closed connection closed before receiving response
	Closed CheckError = "closed"

	// CertExpired means the SSL certificate has expired
	CertExpired CheckError = "cert-expired"

	// CertSelfSigned means the certificate was self-signed
	CertSelfSigned CheckError = "cert-self-signed"

	// CertUntrustedAuthority means the certificate was by an unknown authoriry
	CertUntrustedAuthority CheckError = "cert-untrusted-authority"

	// CertWrongHost means the host did not match the certificate
	CertWrongHost CheckError = "cert-wrong-host"

	// CertIncompleteChain means the certificate chain is incomplete
	CertIncompleteChain CheckError = "cert-incomplete-chain"

	// TLSAlert tls protocol or other tls certificate error
	TLSAlert CheckError = "tls_alert"

	// UnsupportedSchema schema error
	UnsupportedSchema CheckError = "unsupported_schema"
)

// ToString converts an error to a string
func (err CheckError) ToString() string {
	return string(err)
}
