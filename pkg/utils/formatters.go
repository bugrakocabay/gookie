package utils

import "time"

func IntToBool(i int64) bool {
	return i == 1
}

func SameSiteFormat(i string) string {
	switch i {
	case "-1":
		return "Unspecified"
	case "0":
		return "None"
	case "1":
		return "Lax"
	case "2":
		return "Strict"
	default:
		return "Unknown"
	}
}

func EpochToTime(i int64) string {
	return time.Unix(i, 0).UTC().Format(time.RFC3339)
}

func IsExpired(i int64) bool {
	return time.Unix(i, 0).Before(time.Now())
}
