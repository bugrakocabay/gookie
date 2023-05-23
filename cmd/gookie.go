package main

import (
	"fmt"

	"gookie/pkg/browser"
)

func main() {
	cookies, err := browser.ReadChromeCookies()
	if err != nil {
		panic(err)
	}

	fmt.Println(cookies)
}
