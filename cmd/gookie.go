package main

import (
	"log"

	"gookie/pkg/data"
	"gookie/pkg/utils"
)

func main() {
	cookieData, err := data.GetCookies()
	if err != nil {
		log.Fatal(err)
	}

	err = utils.JSONSaver(cookieData, "cookies.json")
	if err != nil {
		log.Fatal(err)
	}
}
