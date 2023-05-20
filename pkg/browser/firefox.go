package browser

import (
	"errors"
	"gookie/pkg/utils"
	"os"
	"path/filepath"
	"strings"
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
