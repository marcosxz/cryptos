package cryptos

import "testing"

var aesTestSecret = []byte("aaaaaaaaaaaaaaaa")
var aesTestData = []byte("asdkasjkldjkasdkljasdkljasdkasjdkjasd;lkasl;dk")

func TestAesCFB(t *testing.T) {
	result, err := AesCFBEncrypt(aesTestData, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = AesCFBDecrypt(result, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestAesCBCByPKCS5Padding(t *testing.T) {
	result, err := AesCBCEncryptByPKCS5Padding(aesTestData, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = AesCBCDecryptByPKCS5UnPadding(result, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestAesCBCByPKCS7Padding(t *testing.T) {
	result, err := AesCBCEncryptByPKCS7Padding(aesTestData, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = AesCBCDecryptByPKCS7UnPadding(result, aesTestSecret)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}
