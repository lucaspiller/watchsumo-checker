package checker

import (
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"syscall"

	log "github.com/sirupsen/logrus"

	t "github.com/lucaspiller/watchsumo-checker/types"
)

// UnwrappedError unwraps an error
type UnwrappedError struct {
	Err t.CheckError

	Cert *x509.Certificate
}

// ToString returns the string format of the error
func (e *UnwrappedError) ToString() string {
	return e.Err.ToString()
}

func (c *Checker) unwrapError(err error) UnwrappedError {
	switch err := err.(type) {
	case *url.Error:
		return c.unwrapURLError(err)

	default:
		// Use reflection for non exported errors >_<
		switch reflect.TypeOf(err).String() {
		case "*http.httpError":
			v := reflect.ValueOf(err).Elem()
			return c.unwrapHTTPError(v.FieldByName("err").String(), v.FieldByName("timeout").Bool())

		default:
			return c.unhandledError(err, "error")
		}
	}
}

func (c *Checker) unwrapURLError(err *url.Error) UnwrappedError {
	switch err := err.Err.(type) {
	case x509.CertificateInvalidError:
		if err.Reason == x509.Expired {
			return UnwrappedError{Err: t.CertExpired, Cert: err.Cert}
		}

		log.WithFields(log.Fields{
			"reason": err.Reason,
		}).Info("Unhandled error x509.CertificateInvalidError")

		return UnwrappedError{Err: t.TLSAlert, Cert: err.Cert}

	case x509.UnknownAuthorityError:
		if err.Cert.IsCA {
			return UnwrappedError{Err: t.CertUntrustedAuthority, Cert: err.Cert}
		}

		// Self-signed certificates usually have the SubjectKeyId equal to
		// AuthorityKeyId, this isn't always true though
		if reflect.DeepEqual(err.Cert.SubjectKeyId, err.Cert.AuthorityKeyId) {
			return UnwrappedError{Err: t.CertSelfSigned, Cert: err.Cert}
		}

		return UnwrappedError{Err: t.CertIncompleteChain, Cert: err.Cert}

	case x509.HostnameError:
		return UnwrappedError{Err: t.CertWrongHost, Cert: err.Certificate}

	case *net.OpError:
		return c.unwrapNetOpError(err)

	default:
		if err == io.EOF {
			return UnwrappedError{Err: t.Closed}
		}

		if err.Error() == errMaxRedirects.Error() {
			return UnwrappedError{Err: t.MaxRedirects}
		}

		// Use reflection for non exported errors >_<
		switch reflect.TypeOf(err).String() {
		case "*http.httpError":
			v := reflect.ValueOf(err).Elem()
			return c.unwrapHTTPError(v.FieldByName("err").String(), v.FieldByName("timeout").Bool())

		case "*tls.permamentError", "*tls.permanentError":
			return UnwrappedError{Err: t.TLSAlert}

		default:
			return c.unhandledError(err, "url.Error")
		}
	}
}

func (c *Checker) unwrapNetOpError(err *net.OpError) UnwrappedError {
	switch err := err.Err.(type) {
	case *net.DNSError:
		if err.IsNotFound {
			return UnwrappedError{Err: t.NxDomain}
		}

		return UnwrappedError{Err: t.DNSError}

	case *os.SyscallError:
		if err.Err.Error() == syscall.ECONNRESET.Error() {
			return UnwrappedError{Err: t.Closed}
		}

		if err.Err.Error() == syscall.ECONNREFUSED.Error() {
			return UnwrappedError{Err: t.ConnectionRefused}
		}

		if err.Err.Error() == syscall.EHOSTUNREACH.Error() {
			return UnwrappedError{Err: t.HostUnreachable}
		}

		return c.unhandledError(err, "os.SyscallError")

	default:
		// Use reflection for non exported errors >_<
		switch reflect.TypeOf(err).String() {
		case "tls.alert":
			return UnwrappedError{Err: t.TLSAlert}

		default:
			return c.unhandledError(err, "net.OpError")
		}
	}
}

func (c *Checker) unwrapHTTPError(message string, timeout bool) UnwrappedError {
	if timeout {
		return UnwrappedError{Err: t.Timeout}
	}

	return UnwrappedError{Err: t.UnknownError}
}

func (c *Checker) unhandledError(err error, parent string) UnwrappedError {
	log.WithFields(log.Fields{
		"Ref":    c.Req.Ref,
		"Err":    err,
		"Type":   reflect.TypeOf(err).String(),
		"Parent": parent,
	}).Warn("Unhandled error")
	return UnwrappedError{Err: t.UnknownError}
}
