package main

import (
	"gookie/pkg/utils"

	"gookie/pkg/browser"
)

func main() {
	cookies, err := browser.ReadChromeCookies()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(cookies, "gookies")
	if err != nil {
		panic(err)
	}
}
