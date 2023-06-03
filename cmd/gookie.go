package main

import (
	"gookie/pkg/user"
	"gookie/pkg/utils"
)

func main() {
	data, err := user.ReturnUserData()
	if err != nil {
		panic(err)
	}

	err = utils.JSONSaver(data, "user.json")
	if err != nil {
		panic(err)
	}
}
