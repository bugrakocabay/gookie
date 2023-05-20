package main

import (
	"log"

	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

func main() {
	cookieData, err := browser.ReadBraveCookies()
	if err != nil {
		log.Fatal(err)
	}

	err = utils.JSONSaver(cookieData, "cookies.json")
	if err != nil {
		log.Fatal(err)
	}
}
