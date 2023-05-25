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
	fmt.Println("------------------")
	cookies2, err := browser.ReadBraveCookies()
	if err != nil {
		panic(err)
	}

	fmt.Println(cookies2)
}
