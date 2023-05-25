package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"syscall"
	"unsafe"
)

type Cookie struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	Expires        string `json:"expires"`
	IsExpired      bool   `json:"isExpired"`
	IsSecure       bool   `json:"isSecure"`
	HttpOnly       bool   `json:"httpOnly"`
	EncryptedValue []byte `json:"encryptedValue"`
}

var (
	DLLCrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	DLLKernel32 = syscall.NewLazyDLL("Kernel32.dll")

	PCryptUnprotectData = DLLCrypt32.NewProc("CryptUnprotectData")
	PLocalFree          = DLLKernel32.NewProc("LocalFree")
	aesKey              []byte
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decryptValue(data []byte) ([]byte, error) {
	if bytes.Equal(data[0:3], []byte{'v', '1', '0'}) {
		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, fmt.Errorf("error creating cipher block: %w", err)
		}

		aesGCM, err := cipher.NewGCM(aesBlock)
		if err != nil {
			return nil, fmt.Errorf("error creating GCM: %w", err)
		}

		nonce := data[3:15]
		encryptedData := data[15:]

		plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			return nil, fmt.Errorf("error decrypting value: %w", err)
		}

		return plaintext, nil

	} else {
		var outBlob DataBlob
		r, _, err := PCryptUnprotectData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
		if r == 0 {
			return nil, err
		}
		defer PLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

		return outBlob.toByteArray(), nil
	}
}
