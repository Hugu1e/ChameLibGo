package SE

import (
	"bytes"
	"testing"
)


func Test_AES(t *testing.T){
	key := []byte("1234567812345678") // AES-128

	plainText := new(PlainText)
    plainText.Pt = []byte("Hello world")

    cipherText, err := Encrypt(plainText, key)
    if err != nil {
        t.Log("Encrypt failed:", err)
        return
    }
    t.Log("Encrypted:", string(cipherText.Ct))


    pt, err2 := Decrypt(cipherText, key)
	if err2 != nil {
		t.Log("Decrypt failed:", err2)
		return
	}
	t.Log("Decrypt result:", string(pt.Pt))

	t.Logf("pt.Pt: %s\n", pt.Pt)
	t.Logf("plainText.Pt: %s\n", plainText.Pt)
	
	if !bytes.Equal(pt.Pt, plainText.Pt) {
		t.Error("AES encrypt and decrypt failed")
	}
	
}