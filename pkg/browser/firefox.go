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
	profile, err := getDefaultFirefoxProfile()
	if err != nil {
		return nil, err
	}

	osUser, err := utils.GetCurrentUsername()
	if err != nil {
		return nil, err
	}

	cookiesPath := filepath.Join("C:\\Users", osUser, "AppData\\Roaming\\Mozilla\\Firefox\\Profiles", profile, "cookies.sqlite")

	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	query := `SELECT host as Domain, expiry as Expires, isHttpOnly as HttpOnly, 
			name as Name, path as Path, isSecure as Secure, 
			value as Value FROM moz_cookies;`
	rows, err := dbConn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []Cookie

	for rows.Next() {
		var cookie Cookie
		var expires, httpOnly, secure int64

		err = rows.Scan(&cookie.Domain, &expires, &httpOnly, &cookie.Name,
			&cookie.Path, &secure, &cookie.Value)
		if err != nil {
			return nil, err
		}

		cookie.Expires = utils.EpochToTime(expires)
		cookie.HttpOnly = utils.IntToBool(httpOnly)
		cookie.IsSecure = utils.IntToBool(secure)

		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

func getDefaultFirefoxProfile() (string, error) {
	osUser, err := utils.GetCurrentUsername()
	if err != nil {
		return "", err
	}

	profilesDir := filepath.Join("C:\\Users", osUser, "AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
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
