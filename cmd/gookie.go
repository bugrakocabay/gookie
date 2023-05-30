package main

import (
	"gookie/pkg/utils"

	"gookie/pkg/browser"
)

func main() {
	cookies, err := browser.ReadEdgeCookies()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(cookies, "qwerty.json")
	if err != nil {
		panic(err)
	}
}
