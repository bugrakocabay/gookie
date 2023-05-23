package browser

import (
	"crypto/sha1"
	"database/sql"
	"fmt"

	"github.com/havoc-io/go-keytar"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
	"gookie/pkg/utils"
)

type Cookie struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	Expires   string `json:"expires"`
	IsExpired bool   `json:"isExpired"`
	IsSecure  bool   `json:"isSecure"`
	HttpOnly  bool   `json:"httpOnly"`
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

	rows, err := dbConn.Query("SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly, name as Name, path as Path, is_secure as Secure, value as Value FROM cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name, &cookie.Path, &secure, &cookie.Value)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		cookie.Expires = utils.EpochToTime((expires / 1000000) - 11644473600)
		cookie.IsExpired = utils.IsExpired(expires)
		cookie.HttpOnly = utils.IntToBool(httpOnly)
		cookie.IsSecure = utils.IntToBool(secure)

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

var (
	salt       = "saltysalt"
	iterations = 1003
	keyLength  = 16
)

func getChromeKey() ([]byte, error) {
	keychain, err := keytar.GetKeychain()
	if err != nil {
		return nil, err
	}

	chromePassword, err := keychain.GetPassword("Chrome Safe Storage", "Chrome")
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(chromePassword), []byte(salt), iterations, keyLength, sha1.New)
	return key, nil
}
