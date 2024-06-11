package twitterscraper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"
)

const bearerToken string = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

func isErrorAuthError(code int) bool {
	authErrorCodes := []int{64, 63, 50, 87, 88, 89, 93, 99, 135, 32, 205, 215, 220, 226}
	return slices.Contains(authErrorCodes, code)
}

// RequestAPI get JSON from frontend API and decodes it
func (s *Scraper) RequestAPI(req *http.Request, target interface{}) error {
	s.wg.Wait()
	if s.delay > 0 {
		defer func() {
			s.wg.Add(1)
			go func() {
				time.Sleep(time.Second * time.Duration(s.delay))
				s.wg.Done()
			}()
		}()
	}

	if !s.isLoggedIn {
		if !s.IsGuestToken() || s.guestCreatedAt.Before(time.Now().Add(-time.Hour*3)) {
			err := s.GetGuestToken()
			if err != nil {
				return err
			}
		}
		req.Header.Set("X-Guest-Token", s.guestToken)
	}

	if s.oAuthToken != "" && s.oAuthSecret != "" {
		req.Header.Set("Authorization", s.sign(req.Method, req.URL))
	} else {
		req.Header.Set("Authorization", "Bearer "+s.bearerToken)
	}

	currentToken := s.authTokens[0]

	s.client.Jar.SetCookies(req.URL, []*http.Cookie{
		{Name: "auth_token", Value: currentToken.AuthToken},
		{Name: "ct0", Value: currentToken.CTZero},
	})
	req.Header.Set("X-CSRF-Token", currentToken.CTZero)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		s.rotateToken(req.URL.Path)
		return s.RequestAPI(req, target)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status %s: %s", resp.Status, content)
	}

	if target == nil {
		return nil
	}
	unmarshallErr := json.Unmarshal(content, target)

	if target.(map[string]interface{})["code"] != nil {
		errorCode := int(target.(map[string]interface{})["code"].(float64))
		if isErrorAuthError(errorCode) {
			s.rotateToken(req.URL.Path)
			return s.RequestAPI(req, target)
		}
	}
	rightMeow := time.Now()
	s.delay = 0
	s.authTokens[0].LastUsed[req.URL.Path] = &rightMeow

	if resp.Header.Get("X-Rate-Limit-Remaining") != "" {
		limitRemaining, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Remaining"))
		if err == nil {
			s.authTokens[0].LimitRemaining[req.URL.Path] = &limitRemaining
			if limitRemaining == 0 {
				s.rotateToken(req.URL.Path)
			}
		}
	}

	if resp.Header.Get("X-Rate-Limit-Reset") != "" {
		timestamp, err := strconv.ParseInt(resp.Header.Get("X-Rate-Limit-Reset"), 10, 64)
		if err == nil {
			reset := time.Unix(timestamp, 0)
			s.authTokens[0].NextRefresh[req.URL.Path] = &reset
		}
	}

	return unmarshallErr
}

func (s *Scraper) rotateToken(path string) {
	s.delay = 0
	slices.SortFunc(s.authTokens, func(i, j AuthToken) int {
		// if auth token's limit remaining is nil, it has not been used
		// so it should be at the front of the list
		if i.LimitRemaining == nil {
			return -1
		}
		if j.LimitRemaining == nil {
			return 1
		}

		if i.LimitRemaining[path] == nil {
			return -1
		}
		if j.LimitRemaining[path] == nil {
			return 1
		}

		// at this point, we know both tokens have been used
		// so we sort by limit remaining, descending
		if *i.LimitRemaining[path] > *j.LimitRemaining[path] {
			return -1
		}
		if *i.LimitRemaining[path] < *j.LimitRemaining[path] {
			return 1
		}

		// oops they're the same, so we sort by next refresh
		// the further in the future, the better
		if i.NextRefresh[path] != nil && j.NextRefresh[path] != nil {
			if i.NextRefresh[path].After(*j.NextRefresh[path]) {
				return -1
			}
			if i.NextRefresh[path].Before(*j.NextRefresh[path]) {
				return 1
			}
		}

		// for some reason, one of the next refreshes is nil
		// so we sort by last used, ascending
		if i.LastUsed[path].Before(*j.LastUsed[path]) {
			return -1
		}
		if i.LastUsed[path].After(*j.LastUsed[path]) {
			return 1
		}

		// if all else fails, we just return 0
		return 0
	})

	currentLimitRemaining := s.authTokens[0].LimitRemaining[path]
	if currentLimitRemaining != nil && *currentLimitRemaining == 0 {
		nextRefresh := s.authTokens[0].NextRefresh
		s.delay = int64(time.Until(*nextRefresh[path]).Seconds() + 1)
	}
}

// GetGuestToken from Twitter API
func (s *Scraper) GetGuestToken() error {
	req, err := http.NewRequest("POST", "https://api.twitter.com/1.1/guest/activate.json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.bearerToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status %s: %s", resp.Status, body)
	}

	var jsn map[string]interface{}
	if err := json.Unmarshal(body, &jsn); err != nil {
		return err
	}
	var ok bool
	if s.guestToken, ok = jsn["guest_token"].(string); !ok {
		return fmt.Errorf("guest_token not found")
	}
	s.guestCreatedAt = time.Now()

	return nil
}
