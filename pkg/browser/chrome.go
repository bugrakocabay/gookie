package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func pkcs5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	paddedData := int(src[length-1])
	if paddedData > length {
		return nil, errors.New("invalid padding size")
	}
	return src[:(length - paddedData)], nil
}

func ChromeDecrypt(key []byte, encrypted []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := bytes.Repeat([]byte{' '}, 16)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData, err = pkcs5UnPadding(origData)
	if err != nil {
		return "", err
	}

	return string(origData), nil
}
