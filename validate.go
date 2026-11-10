package fasth2

import "crypto/tls"

// Field validation, following golang.org/x/net/http/httpguts and RFC 9113
// 8.2.1 / 8.3.1. A request that fails it is malformed (RST_STREAM
// PROTOCOL_ERROR): CR, LF or NUL in a field could otherwise reach HTTP/1
// back ends, logs or URLs built from the Host.

var tokenByte, hostByte [256]bool

func init() {
	for c := '0'; c <= '9'; c++ {
		tokenByte[c], hostByte[c] = true, true
	}
	for c := 'a'; c <= 'z'; c++ {
		tokenByte[c], hostByte[c] = true, true
		tokenByte[c-'a'+'A'], hostByte[c-'a'+'A'] = true, true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		tokenByte[c] = true
	}
	for _, c := range "!$%&'()*+,-.:;=@[]_~" {
		hostByte[c] = true
	}
}

type text interface{ ~string | ~[]byte }

// validToken: RFC 9110 token (methods).
func validToken[T text](s T) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenByte[s[i]] {
			return false
		}
	}
	return true
}

// validFieldName: a lowercase token (HTTP/2 field names are lowercase).
func validFieldName[T text](s T) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !tokenByte[c] || ('A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

// validFieldValue rejects control characters except HTAB (so NUL, CR, LF).
func validFieldValue[T text](s T) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// validHost checks the characters of :authority / Host like
// httpguts.ValidHostHeader.
func validHost(s []byte) bool {
	for _, c := range s {
		if !hostByte[c] {
			return false
		}
	}
	return true
}

// validScheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func validScheme(s []byte) bool {
	if len(s) == 0 || !('a' <= s[0]|0x20 && s[0]|0x20 <= 'z') {
		return false
	}
	for _, c := range s[1:] {
		if !(('a' <= c|0x20 && c|0x20 <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validPath: origin-form ("/...") without controls or spaces, or "*" for
// OPTIONS (RFC 9113 8.3.1). Absolute-form is not allowed in HTTP/2.
func validPath(path, method []byte) bool {
	if string(path) == "*" {
		return string(method) == "OPTIONS"
	}
	if len(path) == 0 || path[0] != '/' {
		return false
	}
	for _, c := range path {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// tlsOK reports whether a TLS connection may carry HTTP/2 (RFC 9113 9.2):
// TLS 1.3, or TLS 1.2 with an ephemeral key exchange and an AEAD cipher.
func tlsOK(cs *tls.ConnectionState) bool {
	switch {
	case cs.Version >= tls.VersionTLS13:
		return true
	case cs.Version < tls.VersionTLS12:
		return false
	}
	switch cs.CipherSuite {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return true
	}
	return false
}
