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

func RSAPKCS1Generate(bits int, privateHeaders, publicHeaders map[string]string) (private, public []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	private = x509.MarshalPKCS1PrivateKey(privateKey)
	public, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}
	private, public = rsaToMemory(private, public, privateHeaders, publicHeaders)
	return
}

func RSAPKCS8Generate(bits int, privateHeaders, publicHeaders map[string]string) (private, public []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	public, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}
	private, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}
	private, public = rsaToMemory(private, public, privateHeaders, publicHeaders)
	return
}

func rsaToMemory(private, public []byte, privateHeaders, publicHeaders map[string]string) ([]byte, []byte) {
	private = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: privateHeaders,
		Bytes:   private,
	})
	public = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: publicHeaders,
		Bytes:   public,
	})
	return private, public
}

func RSAParsePKIXPublicKey(public []byte) (*rsa.PublicKey, error) {
	if len(public) == 0 {
		return nil, InvalidRSAPublicKey
	}
	block, _ := pem.Decode(public)
	if block == nil {
		return nil, InvalidRSAPublicKey
	}
	if pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	} else {
		return pubInterface.(*rsa.PublicKey), nil
	}
}

func RSAParsePKCS1PrivateKey(private []byte) (*rsa.PrivateKey, error) {
	if len(private) == 0 {
		return nil, InvalidRSAPrivateKey
	}
	if block, _ := pem.Decode(private); block == nil {
		return nil, InvalidRSAPrivateKey
	} else {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
}

func RSAParsePKCS8PrivateKey(private []byte) (*rsa.PrivateKey, error) {
	if len(private) == 0 {
		return nil, InvalidRSAPrivateKey
	}
	if block, _ := pem.Decode(private); block == nil {
		return nil, InvalidRSAPrivateKey
	} else {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key.(*rsa.PrivateKey), nil
	}
}

func RSAPKCS1v15Encrypt(public, data []byte) ([]byte, error) {
	publicKey, err := RSAParsePKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func RSAPKCS1Decrypt(private, data []byte) ([]byte, error) {
	privateKey, err := RSAParsePKCS1PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}

func RSAPKCS8Decrypt(private, data []byte) ([]byte, error) {
	privateKey, err := RSAParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}

func RSAPKCS1Signature(hash crypto.Hash, private, data []byte) ([]byte, error) {
	privateKey, err := RSAParsePKCS1PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return RSAPKCS1v15Signature(hash, privateKey, data)
}

func RSAPKCS8Signature(hash crypto.Hash, private, data []byte) ([]byte, error) {
	privateKey, err := RSAParsePKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return RSAPKCS1v15Signature(hash, privateKey, data)
}

func RSAPKCS1v15Signature(hash crypto.Hash, private *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashCase := hash.New()
	hashCase.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, private, hash, hashCase.Sum(nil))
}

func RSAPKCS1v15Verify(hash crypto.Hash, public, data, sign []byte) error {
	publicKey, err := RSAParsePKIXPublicKey(public)
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
func RSAPKCS1v15SegmentEncrypt(secret, data []byte) ([]byte, error) {

	/*
		1024位的证书，加密时最大支持117个字节，解密时为128
		2048位的证书，加密时最大支持245个字节，解密时为256
		加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
		解密时支持的最大字节数：证书位数/8（比如：2048位的证书，支持的最大加密字节数：2048/8  = 256）
	*/

	// 解析证书最大加密长度
	var maxEncLen int
	if publicKey, err := RSAParsePKIXPublicKey(secret); err != nil {
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
			encrypt, err := RSAPKCS1v15Encrypt(secret, data[:maxEncLen]) // 截取本次要加密的文本并加密
			if err != nil {
				return nil, err
			}
			buffer.Write(encrypt)   // 写入加密数据
			data = data[maxEncLen:] // 将已加密的文本剔除,留下待加密的文本
		} else {
			encrypt, err := RSAPKCS1v15Encrypt(secret, data)
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
func RSAPKCS1SegmentDecrypt(private, data []byte) ([]byte, error) {

	/*
		1024位的证书，加密时最大支持117个字节，解密时为128
		2048位的证书，加密时最大支持245个字节，解密时为256
		加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
		解密时支持的最大字节数：证书位数/8（比如：2048位的证书，支持的最大加密字节数：2048/8  = 256）
	*/

	// 解析证书最大解密长度
	var maxDecLen int
	if privateKey, err := RSAParsePKCS1PrivateKey(private); err != nil {
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
			decrypt, err := RSAPKCS1Decrypt(private, data[:maxDecLen]) // 截取本次要解密的文本并解密
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)   // 写入加密数据
			data = data[maxDecLen:] // 将已解密的文本剔除,留下待解密的文本
		} else {
			decrypt, err := RSAPKCS1Decrypt(private, data)
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)
		}
		dataLen = len(data) // 重新定义offset,文本长度
	}
	return buffer.Bytes(), nil
}

// 私钥分段解密
func RSAPKCS8SegmentDecrypt(public, data []byte) ([]byte, error) {

	/*
		1024位的证书，加密时最大支持117个字节，解密时为128
		2048位的证书，加密时最大支持245个字节，解密时为256
		加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
		解密时支持的最大字节数：证书位数/8（比如：2048位的证书，支持的最大加密字节数：2048/8  = 256）
	*/

	// 解析证书最大解密长度
	var maxDecLen int
	if privateKey, err := RSAParsePKCS8PrivateKey(public); err != nil {
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
			decrypt, err := RSAPKCS8Decrypt(public, data[:maxDecLen]) // 截取本次要解密的文本并解密
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)   // 写入加密数据
			data = data[maxDecLen:] // 将已解密的文本剔除,留下待解密的文本
		} else {
			decrypt, err := RSAPKCS8Decrypt(public, data)
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypt)
		}
		dataLen = len(data) // 重新定义offset,文本长度
	}
	return buffer.Bytes(), nil
}
