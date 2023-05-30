package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func JSONSaver(data interface{}, fileName string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(jsonData)
	err = os.WriteFile(fileName, jsonData, 0644)
	if err != nil {
		return err
	}

	log.Printf("JSON data saved to file: %s", fileName)
	return nil
}
