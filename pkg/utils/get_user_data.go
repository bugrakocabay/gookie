package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func GetCurrentUsername() (string, error) {
	userProfile := os.Getenv("USERPROFILE")

	if userProfile == "" {
		return "", fmt.Errorf("failed to retrieve USERPROFILE environment variable")
	}

	_, username := filepath.Split(userProfile)
	return username, nil
}

func GetIPData() (string, error) {
	ip, err := fetchData("https://api64.ipify.org")
	if err != nil {
		fmt.Printf("Error retrieving IP: %s", err)
		return "", err
	}

	return ip, nil
}

func GetCountry(ip string) (string, error) {
	country, err := fetchData(fmt.Sprintf("https://ipapi.co/%s/country_name", ip))
	if err != nil {
		fmt.Printf("Error retrieving Country: %s", err)
		return "", err
	}

	return country, nil
}

func GetCity(ip string) (string, error) {
	city, err := fetchData(fmt.Sprintf("https://ipapi.co/%s/city", ip))
	if err != nil {
		fmt.Printf("Error retrieving City: %s", err)
		return "", err
	}

	return city, nil
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
