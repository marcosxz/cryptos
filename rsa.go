package cryptos

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

var (
	InvalidRSAPublicKey  = errors.New("invalid rsa public key")
	InvalidRSAPrivateKey = errors.New("invalid rsa private key")
)

func GenerateRSA(bits int, privateHeaders, publicHeaders map[string]string) (private, public []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	private = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: privateHeaders,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})
	public = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: publicHeaders,
		Bytes:   publicKeyBytes,
	})
	return
}

func ParsePublicKey(secret []byte) (*rsa.PublicKey, error) {
	if len(secret) == 0 {
		return nil, InvalidRSAPublicKey
	}
	block, _ := pem.Decode(secret)
	if block == nil {
		return nil, InvalidRSAPublicKey
	}
	if pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	} else {
		return pubInterface.(*rsa.PublicKey), nil
	}
}

func ParsePrivateKey(secret []byte) (*rsa.PrivateKey, error) {
	if len(secret) == 0 {
		return nil, InvalidRSAPrivateKey
	}
	if block, _ := pem.Decode(secret); block == nil {
		return nil, InvalidRSAPrivateKey
	} else {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
}

func RSAEncrypt(data, secret []byte) ([]byte, error) {
	publicKey, err := ParsePublicKey(secret)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func RSADecrypt(data, secret []byte) ([]byte, error) {
	privateKey, err := ParsePrivateKey(secret)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}

func RSASignature(data, secret []byte, hash crypto.Hash) ([]byte, error) {
	privateKey, err := ParsePrivateKey(secret)
	if err != nil {
		return nil, err
	}
	hashCase := hash.New()
	hashCase.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashCase.Sum(nil))
}

func RSAVerify(data, sign, secret []byte, hash crypto.Hash) error {
	publicKey, err := ParsePublicKey(secret)
	if err != nil {
		return err
	}
	hashCase := hash.New()
	hashCase.Write(data)
	return rsa.VerifyPKCS1v15(publicKey, hash, hashCase.Sum(nil), sign)
}

// 格式话密钥文件
// 主要是读取的时候不换行的话,会在pem.Decode()的时候出现密钥不通过
func RSAFormat(src string, buffer *bytes.Buffer) {
	// 去除所有的'\n'
	// 去除头尾格式
	// 截取出中间数据
	srcText := strings.Replace(src, "\n", "", -1) // 先去除所有的'\n'
	var begin, end string
	if strings.Contains(srcText, "-----BEGIN") &&
		strings.Contains(srcText, "-----END") { // 去除头尾格式，截取出中间数据
		texts := strings.Split(srcText, "-----")
		srcText, begin, end = texts[2], texts[1], texts[3]
	}
	// 定义换行长度
	// 定义偏移量
	// 定义换行文本长度
	// 定义换行结果集
	bits := 64
	offset := 0
	textLen := len(srcText)
	// begin
	if begin != "" {
		buffer.WriteString("-----")
		buffer.WriteString(begin)
		buffer.WriteString("-----\n")
	}
	// 指定的位置数据加入'\n'
	for i := 0; textLen-offset > 0; offset = i * bits {
		if textLen-offset > bits {
			buffer.WriteString(srcText[offset:offset+bits] + "\n")
		} else {
			buffer.WriteString(srcText[offset:textLen] + "\n")
		}
		i++
	}
	// end
	if end != "" {
		buffer.WriteString("-----")
		buffer.WriteString(end)
		buffer.WriteString("-----\n")
	}
}

// 为密钥文件内容添加BlockType
func RSAAddBlockType(src, blockType string) string {
	src = strings.TrimSuffix(src, "\n")
	src = strings.TrimPrefix(src, "\n")
	result := "-----BEGIN " + blockType + "-----\n"
	result += src
	result += "\n-----END " + blockType + "-----\n"
	return result
}

// 公钥分段加密
func RSASegmentEncrypt(data, secret []byte) ([]byte, error) {

	/*
		1024位的证书，加密时最大支持117个字节，解密时为128
		2048位的证书，加密时最大支持245个字节，解密时为256
		加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
		解密时支持的最大字节数：证书位数/8（比如：2048位的证书，支持的最大加密字节数：2048/8  = 256）
	*/

	// 解析证书最大加密长度
	var maxEncLen int
	if publicKey, err := ParsePublicKey(secret); err != nil {
		return nil, err
	} else {
		maxEncLen = publicKey.N.BitLen()/8 - 11
	}
	// 获取待加密数据长度
	dataLen := len(data)
	// 获取分段的最大次数
	maxSegmentCount := dataLen / maxEncLen
	if dataLen%maxEncLen > 0 {
		maxSegmentCount++
	}
	// 分段加密
	buffer := new(bytes.Buffer)
	for i := 0; i < maxSegmentCount; i++ {
		if dataLen-maxEncLen > 0 { // 如果当前的加密下标小于文本长度,则表示可以正常截取,否则就只能截取当前的文本长度
			encrypt, err := RSAEncrypt(data[:maxEncLen], secret) // 截取本次要加密的文本并加密
			if err != nil {
				return nil, err
			}
			buffer.Write(encrypt)   // 写入加密数据
			data = data[maxEncLen:] // 将已加密的文本剔除,留下待加密的文本
		} else {
			encrypt, err := RSAEncrypt(data, secret)
			if err != nil {
				return nil, err
			}
			buffer.Write(encrypt)
		}
		dataLen = len(data) // 重新定义offset,文本长度
	}
	return buffer.Bytes(), nil
}

// 私钥分段解密
func RSASegmentDecrypt(data, secret []byte) ([]byte, error) {

	/*
		1024位的证书，加密时最大支持117个字节，解密时为128
		2048位的证书，加密时最大支持245个字节，解密时为256
		加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
		解密时支持的最大字节数：证书位数/8（比如：2048位的证书，支持的最大加密字节数：2048/8  = 256）
	*/

	// 解析证书最大解密长度
	var maxDecLen int
	if privateKey, err := ParsePrivateKey(secret); err != nil {
		return nil, err
	} else {
		maxDecLen = privateKey.N.BitLen() / 8
	}
	// 获取待解密数据长度
	dataLen := len(data)
	// 获取分段的最大次数
	maxSegmentCount := dataLen / maxDecLen
	if dataLen%maxDecLen > 0 {
		maxSegmentCount++
	}
	// 分段解密
	buffer := new(bytes.Buffer)
	for i := 0; i < maxSegmentCount; i++ {
		if dataLen-maxDecLen > 0 { // 如果当前的解密下标小于文本长度,则表示可以正常截取,否则就只能截取当前的文本长度
			decrypt, err := RSADecrypt(data[:maxDecLen], secret) // 截取本次要解密的文本并解密
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)   // 写入加密数据
			data = data[maxDecLen:] // 将已解密的文本剔除,留下待解密的文本
		} else {
			decrypt, err := RSADecrypt(data, secret)
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)
		}
		dataLen = len(data) // 重新定义offset,文本长度
	}
	return buffer.Bytes(), nil
}
