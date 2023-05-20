package browser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gookie/pkg/utils"
)

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
