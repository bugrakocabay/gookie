package main

import (
	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

func main() {
	cookies, err := browser.ReadEdgeCookies()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(cookies, "file.json")
	if err != nil {
		panic(err)
	}
}
