package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"fmt"
	"github.com/keybase/go-keychain"
	"log"
)

type Cookie struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	SameSite       string `json:"sameSite"`
	Expires        int64  `json:"expires"`
	Secure         int64  `json:"secure"`
	HttpOnly       int64  `json:"httpOnly"`
	Session        any    `json:"session"`
	EncryptedValue []byte `json:"encryptedValue"`
}

const (
	length = 16
	iv     = "                "
)

func getCookies() (cookies []Cookie, err error) {
	osUser, _ := getOsUserData()
	cookiesPath := fmt.Sprintf("/Users/%s/Library/Application Support/Google/Chrome/Default/Cookies", osUser.Username)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query("SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly, name as Name, path as Path, samesite as SameSite, is_secure as Secure, is_persistent as Session, value as Value, encrypted_value as EncryptedValue FROM cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cookie Cookie
		err = rows.Scan(&cookie.Domain, &cookie.Expires, &cookie.HttpOnly, &cookie.Name, &cookie.Path, &cookie.SameSite, &cookie.Secure, &cookie.Session, &cookie.Value, &cookie.EncryptedValue)
		if err != nil {
			log.Printf("Error scanning row: %s", err)
		}

		switch cookie.SameSite {
		case "-1":
			cookie.SameSite = "None"
		case "0":
			cookie.SameSite = "Unspecified"
		case "1":
			cookie.SameSite = "Strict"
		case "2":
			cookie.SameSite = "Lax"
		default:
			cookie.SameSite = "Unknown"
		}
		cookie.Expires = (cookie.Expires / 1000000) - 11644473600
		cookie.decryptCookie()

		cookies = append(cookies, cookie)
	}

	return
}

func (c *Cookie) decryptCookie() {
	if c.Value > "" {
		return
	}

	if len(c.EncryptedValue) > 0 {
		var decryptedValue = decryptValue(c.EncryptedValue)
		c.Value = decryptedValue
	}
}

func decryptValue(encryptedValue []byte) string {
	if bytes.Equal(encryptedValue[0:3], []byte{'v', '1', '0'}) {
		encryptedValue = encryptedValue[3:]
		key, err := getDecryptionKey()
		if err != nil {
			log.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}

		decrypted := make([]byte, len(encryptedValue))
		cbc := cipher.NewCBCDecrypter(block, []byte(iv))
		cbc.CryptBlocks(decrypted, encryptedValue)

		plainText, err := aesStripPadding(decrypted)
		if err != nil {
			fmt.Println("Error decrypting:", err)
			return ""
		}
		return string(plainText)
	} else {
		return ""
	}
}

func aesStripPadding(data []byte) ([]byte, error) {
	if len(data)%length != 0 {
		return nil, fmt.Errorf("decrypted data block length is not a multiple of %d", length)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("invalid last block padding length: %d", paddingLen)
	}
	return data[:len(data)-paddingLen], nil
}

func getDecryptionKey() ([]byte, error) {
	var err error

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("Chrome Safe Storage")
	query.SetAccount("Chrome")
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return []byte{}, err
	} else if len(results) != 1 {
		return []byte{}, fmt.Errorf("key not found")
	}

	return results[0].Data, nil
}
