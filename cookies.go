package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/havoc-io/go-keytar"
	"golang.org/x/crypto/pbkdf2"
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

var (
	salt       = "saltysalt"
	iterations = 1003
	keyLength  = 16
)

func getDerivedKey() ([]byte, error) {
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

func PKCS5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	paddedData := int(src[length-1])
	if paddedData > length {
		return nil, errors.New("invalid padding size")
	}
	return src[:(length - paddedData)], nil
}

func chromeDecrypt(key []byte, encrypted []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := bytes.Repeat([]byte{' '}, 16)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData, err = PKCS5UnPadding(origData)
	if err != nil {
		return "", err
	}

	return string(origData), nil
}

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
		if len(cookie.EncryptedValue) > 0 {
			derivedKey, err := getDerivedKey()
			cookie.Value, err = chromeDecrypt(derivedKey, cookie.EncryptedValue[3:])
			if nil != err {
				log.Fatal(err)
				return nil, err
			}
		}

		cookies = append(cookies, cookie)
	}
	return
}
