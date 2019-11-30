package cryptos

import (
	"crypto"
)

func Sha1(data []byte) []byte {
	return Hash(data, crypto.SHA1)
}

func Sha256(data []byte) []byte {
	return Hash(data, crypto.SHA256)
}

func Sha512(data []byte) []byte {
	return Hash(data, crypto.SHA512)
}

func Sha1Hex(data []byte) string {
	return HashHex(data, crypto.SHA1)
}

func Sha256Hex(data []byte) string {
	return HashHex(data, crypto.SHA256)
}

func Sha512Hex(data []byte) string {
	return HashHex(data, crypto.SHA512)
}
