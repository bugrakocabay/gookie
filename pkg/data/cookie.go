package data

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

type Cookie struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	SameSite       string `json:"sameSite"`
	Expires        string `json:"expires"`
	IsExpired      bool   `json:"isExpired"`
	IsSecure       bool   `json:"isSecure"`
	HttpOnly       bool   `json:"httpOnly"`
	EncryptedValue []byte `json:"encryptedValue"`
}

func GetCookies() ([]Cookie, error) {
	osUser, err := utils.GetOsUserData()
	if err != nil {
		return nil, err
	}
	cookiesPath := fmt.Sprintf("/Users/%s/Library/Application Support/Google/Chrome/Default/Cookies", osUser.Username)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query("SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly, name as Name, path as Path, samesite as SameSite, is_secure as Secure, value as Value, encrypted_value as EncryptedValue FROM cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name, &cookie.Path, &cookie.SameSite, &secure, &cookie.Value, &cookie.EncryptedValue)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		cookie.SameSite = utils.SameSiteFormat(cookie.SameSite)
		cookie.Expires = utils.EpochToTime((expires / 1000000) - 11644473600)
		cookie.IsExpired = utils.IsExpired(expires)
		cookie.HttpOnly = utils.IntToBool(httpOnly)
		cookie.IsSecure = utils.IntToBool(secure)

		if len(cookie.EncryptedValue) > 0 {
			derivedKey, err := utils.GetChromeKey()
			if err != nil {
				return nil, err
			}
			cookie.Value, err = browser.ChromeDecrypt(derivedKey, cookie.EncryptedValue[3:])
			if err != nil {
				return nil, err
			}
		}

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}
