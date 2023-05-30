package browser

import (
	"database/sql"
	"fmt"
	"gookie/pkg/utils"
	"path/filepath"
)

func ReadEdgeCookies() ([]Cookie, error) {
	osUser, err := utils.GetCurrentUsername()
	if err != nil {
		return nil, err
	}

	cookiesPath := filepath.Join("C:\\Users", osUser, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies")
	dbConn, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&mode=ro", cookiesPath))
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()
	query := `SELECT host_key as Domain, expires_utc as Expires, is_httponly as HttpOnly, 
			name as Name, path as Path, is_secure as Secure, 
			value as Value FROM cookies;`
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
