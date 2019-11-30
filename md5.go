package cryptos

import (
	"crypto"
)

func MD5(data []byte) []byte {
	return Hash(data, crypto.MD5)
}

func MD5Hex(data []byte) string {
	return HashHex(data, crypto.MD5)
}

func MD5For16Hex(data []byte) string {
	return MD5Hex(data)[8:24]
}
