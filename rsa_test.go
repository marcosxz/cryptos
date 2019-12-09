package cryptos

import (
	"bytes"
	"crypto"
	"strings"
	"testing"
)

var rsaTestData = []byte("" +
	"{\"code\":\"10000\",\"msg\":\"Success\",\"out_trade_no\":\"8375247728283648\",\"qr_code\":\"dasdkjsdkljasdkljaskdas\"}" +
	"{\"code\":\"10000\",\"msg\":\"Success\",\"out_trade_no\":\"8375247728283648\",\"qr_code\":\"dasdkjsdkljasdkljaskdas\"}" +
	"{\"code\":\"10000\",\"msg\":\"Success\",\"out_trade_no\":\"8375247728283648\",\"qr_code\":\"dasdkjsdkljasdkljaskdas\"}")

func TestRSAPKCS1Generate(t *testing.T) {
	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("private key:%s \n", string(private))
	t.Logf("public key:%s \n", string(public))
}

func TestRSAParsePKCS1Key(t *testing.T) {

	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	privateKey, err := RSAParsePKCS1PrivateKey(private)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(privateKey.Size())
	t.Log(privateKey.N.BitLen())

	publicKey, err := RSAParsePKIXPublicKey(public)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(publicKey.Size())
	t.Log(publicKey.N.BitLen())
}

func TestRSAPKCS1EncryptDecrypt(t *testing.T) {

	private, public, err := RSAPKCS1Generate(4096, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result, err := RSAPKCS1v15Encrypt(public, rsaTestData)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = RSAPKCS1Decrypt(private, result)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestRSAPKCS1SignatureVerify(t *testing.T) {
	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	sign, err := RSAPKCS1Signature(crypto.SHA256, private, rsaTestData)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(sign))

	err = RSAPKCS1v15Verify(crypto.SHA256, public, rsaTestData, sign)
	if err != nil {
		t.Error(err)
		t.Log("rsa verify failed")
		t.FailNow()
	}

	t.Log("rsa verify success")
}

func TestRSAPKCS1SegmentEncrypt(t *testing.T) {
	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result, err := RSAPKCS1v15SegmentEncrypt(public, rsaTestData)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = RSAPKCS1SegmentDecrypt(private, result)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestRSAFormat(t *testing.T) {

	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(private))
	t.Log(string(public))

	private = []byte(strings.ReplaceAll(string(private), "\n", ""))
	public = []byte(strings.ReplaceAll(string(public), "\n", ""))

	t.Log(string(private))
	t.Log(string(public))

	privateKey, err := RSAParsePKCS1PrivateKey(private)
	if err != nil {
		t.Log("before rsa format parse private key error:", err)
		var buffer = new(bytes.Buffer)
		RSAFormat(string(private), buffer)
		t.Log(buffer.String())
		privateKey, err := RSAParsePKCS1PrivateKey(buffer.Bytes())
		if err != nil {
			t.Log("after rsa format parse private key error:", err)
		} else {
			t.Log("after rsa format parse private key success:", privateKey)
		}
	} else {
		t.Log("before rsa format parse private key success:", privateKey)
	}

	publicKey, err := RSAParsePKIXPublicKey(public)
	if err != nil {
		t.Log("before rsa format parse public key error:", err)
		var buffer = new(bytes.Buffer)
		RSAFormat(string(public), buffer)
		publicKey, err := RSAParsePKIXPublicKey(buffer.Bytes())
		if err != nil {
			t.Log("after rsa format parse public key error:", err)
		} else {
			t.Log("after rsa format parse public key success:", publicKey)
		}
	} else {
		t.Log("before rsa format parse public key success:", publicKey)
	}
}

func TestRSAAddBlockType(t *testing.T) {
	private, public, err := RSAPKCS1Generate(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(private))
	t.Log(string(public))

	privateKey := strings.ReplaceAll(string(private), "-----BEGIN RSA PRIVATE KEY-----\n", "")
	publicKey := strings.ReplaceAll(string(public), "-----BEGIN RSA PUBLIC KEY-----\n", "")
	privateKey = strings.ReplaceAll(privateKey, "-----END RSA PRIVATE KEY-----\n", "")
	publicKey = strings.ReplaceAll(publicKey, "-----END RSA PUBLIC KEY-----\n", "")

	privateKey = RSAAddBlockType(privateKey, "RSA PRIVATE KEY")
	publicKey = RSAAddBlockType(publicKey, "RSA PUBLIC KEY")

	t.Log(privateKey)
	t.Log(publicKey)
}
