package twitterscraper_test

import (
	"testing"

	twitterscraper "github.com/ppramesi/twitter-scraper/twitterscraper"
)

func TestTokenEncrypt(t *testing.T) {
	tokens := []map[string]string{
		{"auth_token": "aaaaaaaaaaaaa", "ct_zero": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"auth_token": "bbbbbbbbbbbbb", "ct_zero": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"auth_token": "ccccccccccccc", "ct_zero": "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		{"auth_token": "ddddddddddddd", "ct_zero": "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		{"auth_token": "eeeeeeeeeeeee", "ct_zero": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		{"auth_token": "fffffffffffff", "ct_zero": "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	}
	tokens2 := twitterscraper.NewAuthTokensFromJSON(tokens)
	err := twitterscraper.EncryptAndSaveTokens(tokens2, "tokens", "b830addbeb7114dc6ffd4ddb62d7374f")
	if err != nil {
		t.Errorf("EncryptAndSaveTokens() error = %v", err)
	}
}

func TestTokenDecrypt(t *testing.T) {
	tokens, err := twitterscraper.LoadAndDecryptTokens("tokens", "b830addbeb7114dc6ffd4ddb62d7374f")
	if err != nil {
		t.Errorf("LoadAndDecryptTokens() error = %v", err)
	}
	if len(tokens) != 6 {
		t.Errorf("Expected 6 tokens, got %d", len(tokens))
	}
}
