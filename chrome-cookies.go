package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/pbkdf2"
)

type Cookie struct {
	creationUtc    int
	hostKey        string
	name           string
	value          string
	path           string
	expiresUtc     int
	isSecure       int
	isHttponly     int
	lastAccessUtc  int
	hasExpires     int
	isPersistent   int
	priority       int
	encryptedValue []byte
	samesite       int
	sourceScheme   int
}

type SetCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int    `json:"expires"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

var (
	SALT       = "saltysalt"
	ITERATIONS = 1003
	KEYLENGTH  = 16
	IV         = "                "
)

func (cookie *Cookie) DecryptedValue() string {
	if cookie.value > "" {
		return cookie.value
	}

	if len(cookie.encryptedValue) > 0 {
		encryptedValue := cookie.encryptedValue[3:]
		return decryptValue(encryptedValue)
	}

	return ""
}

func decryptValue(encryptedValue []byte) string {
	password, _ := keyring.Get("Chrome Safe Storage", "Chrome")
	key := pbkdf2.Key([]byte(password), []byte(SALT), ITERATIONS, KEYLENGTH, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	decrypted := make([]byte, len(encryptedValue))
	cbc := cipher.NewCBCDecrypter(block, []byte(IV))
	cbc.CryptBlocks(decrypted, encryptedValue)

	plainText, err := aesStripPadding(decrypted)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return ""
	}
	return string(plainText)
}

func aesStripPadding(data []byte) ([]byte, error) {
	if len(data)%KEYLENGTH != 0 {
		return nil, fmt.Errorf("decrypted data block length is not a multiple of %d", KEYLENGTH)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("invalid last block padding length: %d", paddingLen)
	}
	return data[:len(data)-paddingLen], nil
}

func main() {
	var domain = flag.String("d", "", "-d domain")
	flag.Parse()
	home, _ := os.UserHomeDir()
	DbConnection, _ := sql.Open("sqlite3", home+"/Library/Application Support/Google/Chrome/Default/Cookies")

	var q = `
	  SELECT
			creation_utc,
			host_key,
			name,
			value,
			path,
			expires_utc,
			is_secure,
			is_httponly,
			last_access_utc,
			has_expires,
			is_persistent,
			priority,
			encrypted_value,
			samesite,
			source_scheme
		FROM cookies
		WHERE host_key like '%` + *domain + `' ORDER BY LENGTH(path) DESC, creation_utc ASC`

	rows, _ := DbConnection.Query(q)

	defer rows.Close()
	var cookies []SetCookie
	for rows.Next() {
		var cookie Cookie
		err := rows.Scan(
			&cookie.creationUtc,
			&cookie.hostKey,
			&cookie.name,
			&cookie.value,
			&cookie.path,
			&cookie.expiresUtc,
			&cookie.isSecure,
			&cookie.isHttponly,
			&cookie.lastAccessUtc,
			&cookie.hasExpires,
			&cookie.isPersistent,
			&cookie.priority,
			&cookie.encryptedValue,
			&cookie.samesite,
			&cookie.sourceScheme,
		)

		if err != nil {
			log.Println(err)
		}

		var setCookie SetCookie
		setCookie.Name = cookie.name
		setCookie.Value = cookie.DecryptedValue()
		setCookie.Domain = cookie.hostKey
		setCookie.Path = cookie.path
		setCookie.Expires = cookie.expiresUtc
		setCookie.HTTPOnly = map[bool]bool{true: true, false: false}[cookie.isHttponly == 0]
		setCookie.Secure = map[bool]bool{true: true, false: false}[cookie.isSecure == 0]

		cookies = append(
			cookies,
			setCookie,
		)
	}

	profJSON, _ := json.Marshal(cookies)
	out := new(bytes.Buffer)
	json.Indent(out, profJSON, "", "  ")
	fmt.Println(out.String())
}
