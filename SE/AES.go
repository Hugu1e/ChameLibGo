package SE

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type CipherText struct {
	Ct []byte
}
func (ct *CipherText) CopyFrom(other *CipherText) *CipherText {
    if len(ct.Ct) < len(other.Ct) {
        ct.Ct = make([]byte, len(other.Ct))
    }
    copy(ct.Ct, other.Ct)
    return ct
}

type PlainText struct {
	Pt []byte
}

func NewPlainText(m []byte) *PlainText {
    pt := new(PlainText)
    copy(pt.Pt, m)
    return pt
}

func Encrypt(plaintext *PlainText, key []byte) (*CipherText, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

	pl := []byte(plaintext.Pt)

    // PKCS7Padding
    pl = PKCS7Padding(pl, block.BlockSize())

    // IV
    ciphertext := make([]byte, aes.BlockSize+len(pl))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    // CBC mode
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], pl)

	ct := new(CipherText)
    // Base64 encode
    ct.Ct = []byte(base64.StdEncoding.EncodeToString(ciphertext))

	return ct, nil
}

// PKCS7Padding
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func Decrypt(ciphertext *CipherText, key []byte) (*PlainText, error) {
    data, err := base64.StdEncoding.DecodeString(string(ciphertext.Ct))
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(data) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(data, data)

    // PKCS7UnPadding
    data = PKCS7UnPadding(data, block.BlockSize())

	pt := new(PlainText)
	pt.Pt = data

    return pt, nil
}

// PKCS7UnPadding
func PKCS7UnPadding(data []byte, blockSize int) []byte {
    length := len(data)
    unpadding := int(data[length-1])
    return data[:(length - unpadding)]
}