package cryptos

import (
	"crypto"
	"testing"
)

var hmacTestSecret = []byte("asdkjhaskjdhkjas")
var hmacTestData = []byte("dashkdhlashdaishdkljhaskdijnaskjdhkausjhdkjhasdkjhaskjd")

func TestHmacHash(t *testing.T) {
	md5 := HmacHash(hmacTestData, hmacTestSecret, crypto.MD5)
	sha1 := HmacHash(hmacTestData, hmacTestSecret, crypto.SHA1)
	sha256 := HmacHash(hmacTestData, hmacTestSecret, crypto.SHA256)
	sha512 := HmacHash(hmacTestData, hmacTestSecret, crypto.SHA512)
	t.Logf("md5 %s \n sha1 %s \n sha256 %s \n sha512 %s \n", md5, sha1, sha256, sha512)
}

func TestHmacSha(t *testing.T) {
	sha1 := HmacSha1(hmacTestData, hmacTestSecret)
	sha256 := HmacSha256(hmacTestData, hmacTestSecret)
	sha512 := HmacSha512(hmacTestData, hmacTestSecret)
	t.Logf("sha1 %s \n sha256 %s \n sha512 %s \n", sha1, sha256, sha512)
}
