package utils

import (
	"crypto/sha1"

	"github.com/havoc-io/go-keytar"
	"golang.org/x/crypto/pbkdf2"
)

var (
	salt       = "saltysalt"
	iterations = 1003
	keyLength  = 16
)

func GetChromeKey() ([]byte, error) {
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

func GetBraveKey() ([]byte, error) {
	keychain, err := keytar.GetKeychain()
	if err != nil {
		return nil, err
	}
	bravePassword, err := keychain.GetPassword("Brave Safe Storage", "Brave")
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(bravePassword), []byte(salt), iterations, keyLength, sha1.New)
	return key, nil
}
