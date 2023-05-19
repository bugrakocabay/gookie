package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"gookie/pkg/data"
)

func main() {
	cookieData, err := data.GetCookies()
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
