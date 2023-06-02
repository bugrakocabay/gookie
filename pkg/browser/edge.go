package browser

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gookie/pkg/utils"
	"os"
	"path/filepath"
)

/*
	func ReadEdgeCookies() ([]Cookie, error) {
		osUser, err := utils.GetCurrentUsername()
		if err != nil {
			return nil, err
		}

		cookiesPath := filepath.Join("C:\\Users", osUser, "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies")
		dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
		if err != nil {
			return nil, err
		}
		defer dbConn.Close()

		err = getAesGCMKeyEdge()
		if err != nil {
			return nil, err
		}
		rows, err := dbConn.Query(`SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly,
				name as Name, path as Path, is_secure as Secure,
				value as Value, encrypted_value as EncryptedValue FROM cookies;`)
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
				return nil, err
			}

			cookie.Expires = utils.EpochToTime(expires)
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
*/
func ReadEdgePasswords() ([]Password, error) {
	osUser, err := utils.GetCurrentUsername()
	if err != nil {
		return nil, err
	}
	passwordsPath := filepath.Join("C:\\Users", osUser, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data")

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", passwordsPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	err = getAesGCMKeyEdge()
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query(`SELECT origin_url as URL, username_value as Username, password_value as Password FROM logins;`)
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

func getAesGCMKeyEdge() error {
	path, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("error getting user cache directory: %w", err)
	}

	localStatePath := filepath.Join(path, "\\Microsoft\\Edge\\User Data\\Local State")
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
