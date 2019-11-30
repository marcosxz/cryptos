package cryptos

import "testing"

var md5TestData = []byte("hashdkjahsdyhkasjhdkjhaskjdhkjasyhdkjhasjdhs")

func TestMD5(t *testing.T) {
	md5 := MD5(md5TestData)
	md5Hex := MD5Hex(md5TestData)
	md5For16Hex := MD5For16Hex(md5TestData)
	t.Logf("md5 %s \n md5Hex %s \n md5For16Hex %s \n", string(md5), md5Hex, md5For16Hex)
}
