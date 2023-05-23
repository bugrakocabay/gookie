package main

import (
	"fmt"
	"gookie/pkg/browser"
)

func main() {
	firefoxCookies, err := browser.ReadChromeCookies()
	if err != nil {
		panic(err)
	}

	fmt.Println(firefoxCookies)
}
