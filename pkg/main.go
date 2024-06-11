package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path"
	"strings"

	twitterscraper "github.com/ppramesi/twitter-scraper/twitterscraper"
)

var (
	EncryptionKey = ""
)

func readAuthTokensCsvFile(filename string) []twitterscraper.AuthToken {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		panic(err)
	}

	authTokens := make([]twitterscraper.AuthToken, len(records))
	for _, record := range records {
		authTokens = append(authTokens, twitterscraper.NewAuthToken(record[0], record[1]))
	}

	return authTokens
}

func main() {
	argsOne := os.Args[0]
	args := os.Args[1:]
	if len(args) != 1 {
		panic("Usage: ./main <username>")
	}

	if args[0] == "ENCRYPT_TOKENS" && strings.Contains(argsOne, "go-build") {
		pwd := os.Getenv("PWD")
		tokensCsvPath := path.Join(pwd, "tokens.csv")
		authTokens := readAuthTokensCsvFile(tokensCsvPath)
		err := twitterscraper.EncryptAndSaveTokens(authTokens, "tokens", EncryptionKey)
		if err != nil {
			panic(err)
		}
	} else {
		tokenPath := fmt.Sprintf("./tokens-%s", args[0])
		ctx := context.Background()
		// check if ./tokens file exists
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			tokenPath = "./tokens"
			if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
				panic("tokens file not found")
				// if not, panics and tell the user
			}
		}
		authTokens, err := twitterscraper.LoadAndDecryptTokens(tokenPath, EncryptionKey)
		if err != nil {
			panic(err)
		}

		scraper := twitterscraper.New(authTokens)
		scraper.SearchTweets(ctx, args[0], 100)
	}
}
