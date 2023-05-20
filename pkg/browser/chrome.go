package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func removePKCS5Padding(src []byte) ([]byte, error) {
	length := len(src)
	paddedData := int(src[length-1])
	if paddedData > length {
		return nil, errors.New("invalid padding size")
	}
	return src[:(length - paddedData)], nil
}

func ChromeDecrypt(key []byte, encrypted []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := bytes.Repeat([]byte{' '}, 16)
	decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
	decryptedData := make([]byte, len(encrypted))
	decrypter.CryptBlocks(decryptedData, encrypted)
	decryptedData, err = removePKCS5Padding(decryptedData)
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}
