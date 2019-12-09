package cryptos

import (
	"crypto"
	"crypto/elliptic"
	"testing"
)

func TestGenerateECDSA(t *testing.T) {
	private, public, err := ECDSAGenerate(elliptic.P256(), nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(string(private))
	t.Log(string(public))
}

func TestECDSASignatureAndVerify(t *testing.T) {
	private, public, err := ECDSAGenerate(elliptic.P256(), nil, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(private))
	t.Log(string(public))

	data := []byte("agdjsajdgsajgdjsagdhjasgdhsagd")
	r, s, err := ECDSASignature(crypto.SHA512, private, data)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("ECDSASignature Successful:(0x%x, 0x%x) \n", r, s)

	err = ECDSAVerify(crypto.SHA512, r, s, public, data)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("ECDSAVerify Successful")
}
