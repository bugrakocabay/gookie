package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func getIPData() {
	ip, err := getData("https://api64.ipify.org")
	if err != nil {
		fmt.Printf("Error retrieving IP: %s", err)
		return
	}

	country, err := getData(fmt.Sprintf("https://ipapi.co/%s/country_name", ip))
	if err != nil {
		fmt.Printf("Error retrieving Country: %s", err)
		return
	}

	time.Sleep(time.Millisecond * 500)

	city, err := getData(fmt.Sprintf("https://ipapi.co/%s/city", ip))
	if err != nil {
		fmt.Printf("Error retrieving City: %s", err)
		return
	}

	fmt.Printf("IP: %s\nCountry: %s\nCity: %s\n", ip, country, city)
}

func getData(url string) (string, error) {
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

func main() {
	getIPData()
}
