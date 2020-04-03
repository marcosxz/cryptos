package cryptos

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"
)

func Hash(data []byte, hash crypto.Hash) []byte {
	hashCase := hash.New()
	hashCase.Write(data)
	return hashCase.Sum(nil)
}

func HashHex(data []byte, hash crypto.Hash) string {
	return hex.EncodeToString(Hash(data, hash))
}
