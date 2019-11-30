package cryptos

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
)

// Hmac-Sha
func HmacHash(data, secret []byte, hash crypto.Hash) string {
	h := hmac.New(hash.New, secret)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Hmac-Sha1
func HmacSha1(data, secret []byte) string {
	return HmacHash(data, secret, crypto.SHA1)
}

// Hmac-Sha256
func HmacSha256(data, secret []byte) string {
	return HmacHash(data, secret, crypto.SHA256)
}

// Hmac-Sha512
func HmacSha512(data, secret []byte) string {
	return HmacHash(data, secret, crypto.SHA512)
}
