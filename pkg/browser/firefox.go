package browser

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gookie/pkg/utils"
)

func ReadFirefoxCookies() ([]Cookie, error) {
	osUser, err := utils.GetOsUserData()
	if err != nil {
		return nil, err
	}

	firefoxProfile, err := getDefaultFirefoxProfile()
	if err != nil {
		return nil, err
	}
	cookiesPath := fmt.Sprintf("/Users/%s/Library/Application Support/Firefox/Profiles/%s/cookies.sqlite", osUser.Username, firefoxProfile)

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query("SELECT host as Domain, expiry as Expires, isHttpOnly as HttpOnly, name as Name, path as Path, samesite as SameSite, isSecure as Secure, value as Value FROM moz_cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name, &cookie.Path, &cookie.SameSite, &secure, &cookie.Value)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		cookie.EncryptedValue = nil
		cookie.IsExpired = utils.IsExpired(expires)

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

func getDefaultFirefoxProfile() (string, error) {
	osUserData, err := utils.GetOsUserData()
	if err != nil {
		return "", err
	}

	profilesDir := filepath.Join("/Users", osUserData.Username, "Library", "Application Support", "Firefox", "Profiles")
	profileFiles, err := os.ReadDir(profilesDir)
	if err != nil {
		return "", err
	}

	for _, profile := range profileFiles {
		if !profile.IsDir() || !strings.Contains(profile.Name(), ".default") {
			continue
		}

		currentProfile, err := os.ReadDir(filepath.Join(profilesDir, profile.Name()))
		if err != nil {
			return "", err
		}

		for _, file := range currentProfile {
			if file.Name() != "cookies.sqlite" {
				continue
			}

			return profile.Name(), nil
		}
	}

	return "", errors.New("could not find default profile")
}

//func GetFirefoxKey() ([]byte, error) {
//	keychain, err := keytar.GetKeychain()
//	if err != nil {
//		return nil, err
//	}
//
//	profileID, err := getDefaultFirefoxProfile()
//	if err != nil {
//		return nil, err
//	}
//	if strings.HasSuffix(profileID, ".default-release") {
//		profileID = strings.TrimSuffix(profileID, ".default-release")
//	}
//
//	firefoxPassword, err := keychain.GetPassword("org.mozilla.firefox", profileID)
//	if err != nil {
//		return nil, err
//	}
//
//	key := pbkdf2.Key([]byte(firefoxPassword), []byte("saltysalt"), 1, 16, sha1.New)
//	return key, nil
//}
