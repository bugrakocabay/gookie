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
	"gookie/pkg/utils"
	"os"
	"path/filepath"
)

type LoginList struct {
	NextId                int                    `json:"nextId"`
	Logins                []Login                `json:"logins"`
	VulnerablePasswords   []interface{}          `json:"potentiallyVulnerablePasswords"`
	DismissedBreachAlerts map[string]interface{} `json:"dismissedBreachAlertsByLoginGUID"`
	Version               int                    `json:"version"`
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

type ASN1Object struct {
	ObjectIdentifier asn1.ObjectIdentifier
	ObjectSequence   []ASN1Sequence
}

type ASN1Sequence struct {
	Content          asn1.RawContent
	ObjectIdentifier asn1.ObjectIdentifier
}

type ASN1SequenceWithEmbedded struct {
	ObjectIdentifier asn1.ObjectIdentifier
	EmbeddedObject   ASN1EmbeddedObject
}

type ASN1SequenceWithBytes struct {
	ObjectIdentifier asn1.ObjectIdentifier
	Data             []byte
}

type ASN1EmbeddedObject struct {
	Data              []byte
	Int1              int
	Int2              int
	ObjectIdentifiers []asn1.ObjectIdentifier
}

type EncryptedData struct {
	KeyIdentifier []byte
	DataSequence  EncryptedDataSequence
	CipherText    []byte
}

type EncryptedDataSequence struct {
	ObjectIdentifier asn1.ObjectIdentifier
	Data             []byte
}

type KeyData struct {
	ASN1ObjectData ASN1Object
	Data           []byte
}

func loadLoginsData(profilePath string) (LoginList, error) {
	var logins LoginList
	jsonData, err := os.ReadFile(filepath.Join(profilePath, "logins.json"))
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

func unpad(data []byte) []byte {
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

	return unpad(plaintext), nil
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

	return x.KeyIdentifier, x.DataSequence.Data, x.CipherText, nil
}

func FirefoxCrackLoginData(profilePath string) ([]Password, error) {
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
	var key KeyData
	var key2 ASN1SequenceWithEmbedded
	var key3 ASN1SequenceWithBytes

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

	if _, err := asn1.Unmarshal(key.ASN1ObjectData.ObjectSequence[0].Content, &key2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	if _, err := asn1.Unmarshal(key.ASN1ObjectData.ObjectSequence[1].Content, &key3); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	entrySalt := key2.EmbeddedObject.Data
	iterationCount := key2.EmbeddedObject.Int1
	keyLength := key2.EmbeddedObject.Int2

	k := sha1.Sum(globalSalt)
	respectKey := pbkdf2.Key(k[:], entrySalt, iterationCount, keyLength, sha256.New)
	iv := append([]byte{4, 14}, key3.Data...)
	cipherT := key.Data

	res, err := decryptAES(cipherT, respectKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES: %w", err)
	}

	logins, err := loadLoginsData(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load logins data: %w", err)
	}

	var credentials []Password
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

		credentials = append(credentials, Password{login.Hostname, string(username), string(password), nil})
	}

	return credentials, nil
}

func getActiveProfilePath() (string, error) {
	path := filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open profiles folder: %v", err)
	}
	defer f.Close()

	dirs, err := f.Readdirnames(0)
	if err != nil {
		return "", fmt.Errorf("failed to read directory names: %v", err)
	}

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

	path = filepath.Join(path, activeDir)

	return path, nil
}

func ReadFirefoxPasswords() ([]Password, error) {
	profilePath, err := getActiveProfilePath()
	if err != nil {
		return nil, err
	}

	credentials, err := FirefoxCrackLoginData(profilePath)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

func ReadFirefoxCookies() ([]Cookie, error) {
	profilePath, err := getActiveProfilePath()
	if err != nil {
		return nil, err
	}

	cookiesPath := filepath.Join(profilePath, "cookies.sqlite")

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
