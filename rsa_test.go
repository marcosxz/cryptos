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

func TestGenerateRSA(t *testing.T) {
	private, public, err := GenerateRSA(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("private key:%s \n", string(private))
	t.Logf("public key:%s \n", string(public))
}

func TestParseKey(t *testing.T) {

	private, public, err := GenerateRSA(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	privateKey, err := ParsePrivateKey(private)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(privateKey.Size())
	t.Log(privateKey.N.BitLen())

	publicKey, err := ParsePublicKey(public)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(publicKey.Size())
	t.Log(publicKey.N.BitLen())
}

func TestRSAEncryptDecrypt(t *testing.T) {

	private, public, err := GenerateRSA(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result, err := RSAEncrypt(rsaTestData, public)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = RSADecrypt(result, private)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestRSASignatureVerify(t *testing.T) {
	private, public, err := GenerateRSA(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	sign, err := RSASignature(rsaTestData, private, crypto.SHA256)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(sign))

	err = RSAVerify(rsaTestData, sign, public, crypto.SHA256)
	if err != nil {
		t.Error(err)
		t.Log("rsa verify failed")
		t.FailNow()
	}

	t.Log("rsa verify success")
}

func TestRSASegmentEncrypt(t *testing.T) {
	private, public, err := GenerateRSA(1024, nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result, err := RSASegmentEncrypt(rsaTestData, public)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))

	result, err = RSASegmentDecrypt(result, private)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(result))
}

func TestRSAFormat(t *testing.T) {

	private, public, err := GenerateRSA(1024, nil, nil)
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

	privateKey, err := ParsePrivateKey(private)
	if err != nil {
		t.Log("before rsa format parse private key error:", err)
		var buffer = new(bytes.Buffer)
		RSAFormat(string(private), buffer)
		t.Log(buffer.String())
		privateKey, err := ParsePrivateKey(buffer.Bytes())
		if err != nil {
			t.Log("after rsa format parse private key error:", err)
		} else {
			t.Log("after rsa format parse private key success:", privateKey)
		}
	} else {
		t.Log("before rsa format parse private key success:", privateKey)
	}

	publicKey, err := ParsePublicKey(public)
	if err != nil {
		t.Log("before rsa format parse public key error:", err)
		var buffer = new(bytes.Buffer)
		RSAFormat(string(public), buffer)
		publicKey, err := ParsePublicKey(buffer.Bytes())
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
	private, public, err := GenerateRSA(1024, nil, nil)
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
