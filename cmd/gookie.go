package main

import (
	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

func main() {
	firefoxCookies, err := browser.ReadFirefoxCookies()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(firefoxCookies, "firefox.json")
}
