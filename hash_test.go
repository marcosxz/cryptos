package cryptos

import (
	"crypto"
	"testing"
)

var hashTestData = []byte("asjdljasdlasjdklasudwjdklhjasikdhjkjaishdkljasdkas")

func TestHash(t *testing.T) {
	md5 := Hash(hashTestData, crypto.MD5)
	sha1 := Hash(hashTestData, crypto.SHA1)
	sha256 := Hash(hashTestData, crypto.SHA256)
	sha512 := Hash(hashTestData, crypto.SHA512)
	t.Logf("md5 %s \n sha1 %s \n sha256 %s \n sha512 %s \n", md5, sha1, sha256, sha512)
}

func TestHashHex(t *testing.T) {
	md5 := HashHex(hashTestData, crypto.MD5)
	sha1 := HashHex(hashTestData, crypto.SHA1)
	sha256 := HashHex(hashTestData, crypto.SHA256)
	sha512 := HashHex(hashTestData, crypto.SHA512)
	t.Logf("md5Hex %s \n sha1Hex %s \n sha256Hex %s \n sha512Hex %s \n", md5, sha1, sha256, sha512)
}
