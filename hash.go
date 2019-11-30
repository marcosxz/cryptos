package cryptos

import (
	"crypto"
	"encoding/hex"
)

func Hash(data []byte, hash crypto.Hash) []byte {
	hashCase := hash.New()
	hashCase.Write(data)
	return hashCase.Sum(nil)
}

func HashHex(data []byte, hash crypto.Hash) string {
	return hex.EncodeToString(Hash(data, hash))
}
