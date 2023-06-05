package main

import (
	"gookie/pkg/browser/chromium"
	"gookie/pkg/user"
	"gookie/pkg/utils"
)

func main() {
	userData, err := user.ReturnUserData()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(userData, "user.json")
	if err != nil {
		panic(err)
	}

	fetcher := chromium.NewBrowserDataFetcher()
	browserData, err := fetcher.GetAllBrowserData()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(browserData, "browser.json")
	if err != nil {
		panic(err)
	}
}
