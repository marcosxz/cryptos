package cryptos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
)

var (
	InvalidECDSAPublicKey  = errors.New("invalid ecdsa public key")
	InvalidECDSAPrivateKey = errors.New("invalid ecdsa private key")
	ECDSAVerifyFailed      = errors.New("ecdsa ecdsa verify failed")
)

func ECDSAGenerate(c elliptic.Curve, privateHeaders, publicHeaders map[string]string) (private, public []byte, err error) {

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return
	}
	public, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}
	private, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return
	}
	private = pem.EncodeToMemory(&pem.Block{
		Type:    "ECDSA PRIVATE KEY",
		Headers: privateHeaders,
		Bytes:   private,
	})
	public = pem.EncodeToMemory(&pem.Block{
		Type:    "ECDSA PUBLIC KEY",
		Headers: publicHeaders,
		Bytes:   public,
	})
	return
}

func ECDSAParsePrivateKey(secret []byte) (*ecdsa.PrivateKey, error) {
	if len(secret) == 0 {
		return nil, InvalidECDSAPrivateKey
	}
	if block, _ := pem.Decode(secret); block == nil {
		return nil, InvalidECDSAPrivateKey
	} else {
		return x509.ParseECPrivateKey(block.Bytes)
	}
}

func ECDSAParsePublicKey(secret []byte) (*ecdsa.PublicKey, error) {
	if len(secret) == 0 {
		return nil, InvalidECDSAPublicKey
	}
	block, _ := pem.Decode(secret)
	if block == nil {
		return nil, InvalidECDSAPublicKey
	}
	if pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	} else {
		return pubInterface.(*ecdsa.PublicKey), nil
	}
}

func ECDSASignature(hash crypto.Hash, private, data []byte) (r, s *big.Int, err error) {
	privateKey, err := ECDSAParsePrivateKey(private)
	if err != nil {
		return
	}
	return ecdsa.Sign(rand.Reader, privateKey, hash.New().Sum(data)[:])
}

func ECDSAVerify(hash crypto.Hash, r, s *big.Int, public, data []byte) error {
	publicKey, err := ECDSAParsePublicKey(public)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(publicKey, hash.New().Sum(data)[:], r, s) {
		return ECDSAVerifyFailed
	}
	return nil
}
