package user

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Data struct {
	Hardware Hardware `json:"hardware"`
	IP       IP       `json:"ip"`
}

type Hardware struct {
	OS           string `json:"os"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	CPU          int    `json:"cpu"`
}

type IP struct {
	IP       string `json:"IP"`
	City     string `json:"City"`
	Region   string `json:"Region"`
	Country  string `json:"Country"`
	Location string `json:"Location"`
	Timezone string `json:"Timezone"`
	ISP      string `json:"ISP"`
}

type OSVersionInfo struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

func ReturnUserData() (Data, error) {
	userIPData, err := fetchIPData()
	if err != nil {
		return Data{}, err
	}

	userHardwareData, err := getOsVersionData()
	if err != nil {
		return Data{}, err
	}

	return Data{
		IP: userIPData,
		Hardware: Hardware{
			OS:           runtime.GOOS,
			Version:      userHardwareData,
			CPU:          runtime.NumCPU(),
			Architecture: runtime.GOARCH,
		},
	}, nil
}

func fetchIPData() (IP, error) {
	response, err := http.Get("https://ipinfo.io")
	if err != nil {
		return IP{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return IP{}, err
	}

	var data IP
	err = json.Unmarshal(body, &data)
	if err != nil {
		return IP{}, err
	}

	return IP{
		IP:       data.IP,
		City:     data.City,
		Region:   data.Region,
		Country:  data.Country,
		Location: data.Location,
		ISP:      data.ISP,
		Timezone: data.Timezone,
	}, nil
}

func getOsVersionData() (string, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	pRtlGetVersion := kernel32.NewProc("GetVersionExW")

	var osvi OSVersionInfo
	osvi.dwOSVersionInfoSize = uint32(unsafe.Sizeof(osvi))

	r1, _, e1 := pRtlGetVersion.Call(uintptr(unsafe.Pointer(&osvi)))
	if r1 != 1 {
		if e1 != nil {
			return "", e1
		}
		return "", syscall.EINVAL
	}
	version := fmt.Sprintf("Windows version %d.%d (Build %d)", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber)
	return version, nil
}
