package checker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"

	"github.com/lucaspiller/watchsumo-checker/types"
)

func certInfoFromTLSConnectionState(tls *tls.ConnectionState) *types.CertInfo {
	return certInfoFromCert(tls.PeerCertificates[0])
}

func certInfoFromCert(cert *x509.Certificate) *types.CertInfo {
	if cert == nil {
		return nil
	}

	return &types.CertInfo{
		Subject:           extractSubject(cert),
		Issuer:            extractIssuer(cert),
		SerialString:      extractSerial(cert),
		Serial:            cert.SerialNumber.Bytes(),
		ValidFrom:         cert.NotBefore,
		ValidTo:           cert.NotAfter,
		Algorithm:         int(cert.SignatureAlgorithm),
		FingerprintSHA256: extractFingerprintSHA256(cert),
	}
}

func extractSubject(cert *x509.Certificate) string {
	// First attempt to parse Subject Alt Name, as clients will typically ignore
	// the Common Name if this is present
	if len(cert.DNSNames) > 5 {
		// Truncate to first 5 SANs
		return strings.Join(cert.DNSNames[:5], " ") + " ..."
	} else if len(cert.DNSNames) > 0 {
		return strings.Join(cert.DNSNames, " ")
	}

	return cert.Subject.CommonName
}

func extractIssuer(cert *x509.Certificate) string {
	cn := cert.Issuer.CommonName

	if len(cert.Issuer.Organization) > 0 {
		on := cert.Issuer.Organization[0]
		return cn + " (" + on + ")"
	}

	return cn
}

func extractSerial(cert *x509.Certificate) string {
	b := cert.SerialNumber.Bytes()
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}

func extractFingerprintSHA256(cert *x509.Certificate) []byte {
	signature := sha256.Sum256(cert.Raw)
	return signature[:]
}
