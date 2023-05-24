package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gookie/pkg/utils"
	"os"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
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
)

var aesKey []byte

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

func getAesGCMKey() []byte {
	var encryptedKey []byte
	var path, _ = os.UserCacheDir()
	var localStateFile = fmt.Sprintf("%s\\Google\\Chrome\\User Data\\Local State", path)

	data, _ := os.ReadFile(localStateFile)
	var localState map[string]interface{}
	json.Unmarshal(data, &localState)

	if localState["os_crypt"] != nil {

		encryptedKey, _ = base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))

		if bytes.Equal(encryptedKey[0:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
			encryptedKey, _ = decryptValue(encryptedKey[5:])
		} else {
			fmt.Print("encrypted_key does not look like DPAPI key\n")
		}
	}

	return encryptedKey
}

func decryptValue(data []byte) ([]byte, error) {
	if bytes.Equal(data[0:3], []byte{'v', '1', '0'}) {
		aesBlock, _ := aes.NewCipher(aesKey)
		aesGCM, _ := cipher.NewGCM(aesBlock)

		nonce := data[3:15]
		encryptedData := data[15:]

		plaintext, _ := aesGCM.Open(nil, nonce, encryptedData, nil)

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

func ReadChromeCookies() ([]Cookie, error) {
	osUser, err := utils.GetCurrentUsername()
	if err != nil {
		return nil, err
	}
	cookiesPath := fmt.Sprintf("C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", osUser)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query("SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly, name as Name, path as Path, is_secure as Secure, value as Value, encrypted_value as EncryptedValue FROM cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name, &cookie.Path, &secure, &cookie.Value, &cookie.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		cookie.Expires = utils.EpochToTime((expires / 1000000) - 11644473600)
		cookie.IsExpired = utils.IsExpired(expires)
		cookie.HttpOnly = utils.IntToBool(httpOnly)
		cookie.IsSecure = utils.IntToBool(secure)
		decrypted, err := decryptValue(cookie.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("error decrypting: %w", err)
		}
		cookie.Value = string(decrypted)

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}
