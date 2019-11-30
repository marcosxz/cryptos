package cryptos

import "testing"

var shaTestData = []byte("hgsdhasbdhjasghdkjhskjhdklhjaskdjkasdsa")

func TestSha(t *testing.T) {
	sha1 := Sha1(shaTestData)
	sha256 := Sha256(shaTestData)
	sha512 := Sha512(shaTestData)
	t.Logf("sha1 %s \n sha256 %s \n sha512 %s \n", string(sha1), string(sha256), string(sha512))
}

func TestShaHex(t *testing.T) {
	sha1Hex := Sha1Hex(shaTestData)
	sha256Hex := Sha256Hex(shaTestData)
	sha512Hex := Sha512Hex(shaTestData)
	t.Logf("sha1Hex %s \n sha256Hex %s \n sha512Hex %s \n", sha1Hex, sha256Hex, sha512Hex)
}
