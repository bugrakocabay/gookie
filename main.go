package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

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

func main() {
	getIPData()
}
