package main

import (
	"fmt"
	"github.com/keybase/go-keychain"
)

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

func main() {
	encryptedKey, err := getEncryptionKey()
	if err != nil {
		fmt.Printf("Error: %s", err)
	} else {
		fmt.Printf("Encrypted Key: %s\n", encryptedKey)
	}
}
