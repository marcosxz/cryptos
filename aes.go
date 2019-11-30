package cryptos

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func AesCFBEncrypt(data, secret []byte) ([]byte, error) {
	encrypted := make([]byte, len(data))
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	iv := secret[:aes.BlockSize]
	encryption := cipher.NewCFBEncrypter(block, iv)
	encryption.XORKeyStream(encrypted, data)
	return encrypted, nil
}

func AesCFBDecrypt(data, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	iv := secret[:aes.BlockSize]
	aesDecryption := cipher.NewCFBDecrypter(block, iv)
	aesDecryption.XORKeyStream(decrypted, data)
	return decrypted, nil
}

func AesCBCEncryptByPKCS7Padding(data, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	iv := secret[:aes.BlockSize]
	padding := AesPKCS7Padding(data, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(padding))
	blockModel.CryptBlocks(cipherText, padding)
	return cipherText, nil
}

func AesCBCDecryptByPKCS7UnPadding(data, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	iv := secret[:aes.BlockSize]
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plantText := make([]byte, len(data))
	blockModel.CryptBlocks(plantText, data)
	plantText = AesPKCS7UnPadding(plantText)
	return plantText, nil
}

func AesCBCEncryptByPKCS5Padding(data, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	padding := AesPKCS5Padding(data, blockSize)
	iv := secret[:aes.BlockSize]
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(padding))
	blockMode.CryptBlocks(cipherText, padding)
	return cipherText, nil
}

func AesCBCDecryptByPKCS5UnPadding(data, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	iv := secret[:aes.BlockSize]
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	blockModel.CryptBlocks(plaintext, data)
	plaintext = AesPKCS5UnPadding(plaintext)
	return plaintext, nil
}

// PKCS7 Padding
func AesPKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// PKCS7 Padding
func AesPKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unPadding := int(plantText[length-1])
	return plantText[:(length - unPadding)]
}

// PKCS5 Padding
func AesPKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// PKCS5 Padding
func AesPKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
