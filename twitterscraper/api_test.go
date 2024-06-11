package twitterscraper_test

import (
	"testing"

	twitterscraper "github.com/ppramesi/twitter-scraper/twitterscraper"
)

func TestGetGuestToken(t *testing.T) {
	scraper := twitterscraper.New([]twitterscraper.AuthToken{})
	if err := scraper.GetGuestToken(); err != nil {
		t.Errorf("getGuestToken() error = %v", err)
	}
	if !scraper.IsGuestToken() {
		t.Error("Expected non-empty guestToken")
	}
}
