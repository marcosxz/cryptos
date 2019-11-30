package cryptos

import (
	"testing"
)

var base64TestData = []byte("aaaaaaasddasdasdasdas你SD卡SD卡垃圾啊塑料袋阿斯加德凉快接啊SD卡拉斯asd")

func TestBase64(t *testing.T) {
	result := Base64Encrypt(base64TestData)
	t.Log(result)

	results, err := Base64Decrypt(result)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(string(results))
}
