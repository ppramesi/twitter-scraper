package twitterscraper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

var (
	EncryptionKey string
)

const (
	IV = "1234567890123456"
)

type AuthToken struct {
	AuthToken      string
	CTZero         string
	LimitRemaining map[string]*int
	LastUsed       map[string]*time.Time
	NextRefresh    map[string]*time.Time
}

func NewAuthTokensFromJSON(json []map[string]string) []AuthToken {
	tokens := make([]AuthToken, len(json))
	for i, j := range json {
		tokens[i] = NewAuthToken(j["auth_token"], j["ct_zero"])
	}
	return tokens
}

func NewAuthTokens(ct0s, authTokens []string) []AuthToken {
	tokens := make([]AuthToken, len(ct0s))
	for i, ct0 := range ct0s {
		tokens[i] = NewAuthToken(authTokens[i], ct0)
	}
	return tokens
}

func NewAuthToken(authToken, ct0 string) AuthToken {
	return AuthToken{
		AuthToken:      authToken,
		CTZero:         ct0,
		LimitRemaining: make(map[string]*int),
		LastUsed:       make(map[string]*time.Time),
		NextRefresh:    make(map[string]*time.Time),
	}
}

func EncryptAndSaveTokens(tokens []AuthToken, filename string, encryptionKey string) error {
	bytes, err := json.Marshal(tokens)
	if err != nil {
		return err
	}

	encrypted, err := encrypt(string(bytes), encryptionKey)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encrypted, 0644)
	if err != nil {
		return err
	}

	return nil
}

func LoadAndDecryptTokens(filename string, encryptionKey string) ([]AuthToken, error) {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	decrypted, err := decrypt(encrypted, encryptionKey)
	if err != nil {
		return nil, err
	}

	var tokens []AuthToken
	err = json.Unmarshal(decrypted, &tokens)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// pkcs5UnPadding  pads a certain blob of data with necessary data to be used in AES block cipher
func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

// GetAESDecrypted decrypts given text in AES 256 CBC
func decrypt(encrypted []byte, encryptionKey string) ([]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("EncryptionKey must be 32 bytes long")
	}

	block, err := aes.NewCipher([]byte(encryptionKey))

	if err != nil {
		return nil, err
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(IV))
	mode.CryptBlocks(encrypted, encrypted)
	encrypted = pkcs5UnPadding(encrypted)

	return encrypted, nil
}

func encrypt(plaintext, encryptionKey string) ([]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryptionKey must be 32 bytes long")
	}

	var plainTextBlock []byte
	length := len(plaintext)

	if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}

	copy(plainTextBlock, plaintext)
	block, err := aes.NewCipher([]byte(encryptionKey))

	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(IV))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	return ciphertext, nil
}
