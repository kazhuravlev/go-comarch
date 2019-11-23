package comarch

import (
	"encoding/json"
	"net/http"
	"time"
)

// parseAccessToken парсит тело ответа на предмет наличия токена
func parseAccessToken(resp *http.Response) (*AccessToken, error) {
	var token accessToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	cookies := map[string]string{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	expiresAt := time.Now().Add(time.Second * time.Duration(token.ExpiresIn))

	publicToken := AccessToken{
		Value:     token.Token,
		ExpiresAt: expiresAt,
		Cookies:   cookies,
	}

	return &publicToken, nil
}
