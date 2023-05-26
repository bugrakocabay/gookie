package main

import (
	"fmt"

	"gookie/pkg/browser"
)

func main() {
	cookies, err := browser.ReadFirefoxCookies()
	if err != nil {
		panic(err)
	}

	fmt.Println(cookies)
}
