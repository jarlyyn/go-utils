package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"encoding/base64"
)

var filledByte = []byte{0}

const IVSize = 16

func formatKey(key []byte, size int) []byte {
	var data = make([]byte, size)
	copy(data, key)
	return data
}
func AESEncrypt(unencrypted []byte, key []byte, iv []byte) (encrypted []byte, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = r.(error)
		}
	}()
	cryptKey := formatKey(key, aes.BlockSize)
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		return
	}
	data := PKCS7Padding(unencrypted, aes.BlockSize)
	crypter := cipher.NewCBCEncrypter(block, iv)
	encrypted = make([]byte, len(data))
	crypter.CryptBlocks(encrypted, data)
	return
}
func AESNonceEncrypt(unencrypted []byte, key []byte) (encrypted []byte, err error) {
	var rawEncrypted []byte
	var IV = make([]byte, IVSize)
	_, err = rand.Read(IV)
	if err != nil {
		return
	}
	rawEncrypted, err = AESEncrypt(unencrypted, key, IV)
	if err != nil {
		return
	}
	encrypted = make([]byte, len(rawEncrypted)+int(IVSize))
	copy(encrypted[:IVSize], IV)
	copy(encrypted[IVSize:], rawEncrypted)
	return
}
func AESEncryptBase64(unencrypted []byte, key []byte, iv []byte) (encrypted string, err error) {
	d, err := AESEncrypt(unencrypted, key, iv)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(d), nil
}
func AESNonceEncryptBase64(unencrypted []byte, key []byte) (encrypted string, err error) {
	d, err := AESNonceEncrypt(unencrypted, key)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(d), nil
}
func AESDecrypt(encrypted []byte, key []byte, iv []byte) (decrypted []byte, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = r.(error)
		}
	}()
	cryptKey := formatKey(key, aes.BlockSize)
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		return
	}
	crypter := cipher.NewCBCDecrypter(block, iv)
	data := make([]byte, len(encrypted))
	crypter.CryptBlocks(data, encrypted)
	decrypted = PKCS7Unpadding(data)
	return
}
func AESNonceDecrypt(encrypted []byte, key []byte) (decrypted []byte, err error) {
	return AESDecrypt(encrypted[IVSize:], key, encrypted[:IVSize])
}
func AESDecryptBase64(encrypted string, key []byte, iv []byte) (decrypted []byte, err error) {
	d, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return
	}
	return AESDecrypt(d, key, iv)
}

func AESNonceDecryptBase64(encrypted string, key []byte) (decrypted []byte, err error) {
	d, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return
	}
	return AESNonceDecrypt(d, key)
}
