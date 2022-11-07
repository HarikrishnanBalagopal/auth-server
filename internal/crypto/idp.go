package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

// GetTokensUsingAuthCode gets access and refresh tokens according to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
func GetTokensUsingAuthCode(_ctx context.Context, idp types.IdentityProvider, authCode, redirectURI string) (types.Tokens, error) {
	tokens := types.Tokens{}
	// prepare the request
	reqParams := url.Values{}
	reqParams.Set("grant_type", "authorization_code")
	reqParams.Set("code", authCode)
	reqParams.Set("redirect_uri", redirectURI)
	reqBody := bytes.NewBufferString(reqParams.Encode())
	tokenEndpoint := idp.CollectedInfo.TokenEndpoint
	reqBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(idp.ClientId+":"+idp.ClientSecret))

	ctx, cancel := context.WithTimeout(_ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, reqBody)
	if err != nil {
		return tokens, fmt.Errorf("failed to prepare a POST request for the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	req.Header.Set(common.AUTHZ_HEADER, reqBasicAuth)
	req.Header.Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_FORM_URL_ENCODED)

	logrus.Debugf("going to send the access token request using authorization_code flow. Request: %+v", req)
	// send the request
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return tokens, fmt.Errorf("failed to send a POST request to the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		getTokenError := ""
		if resp.StatusCode == 400 {
			if bodyBytes, err := io.ReadAll(resp.Body); err == nil {
				errInfo := map[string]interface{}{}
				if err := json.Unmarshal(bodyBytes, &errInfo); err == nil {
					if t2I, ok := errInfo["error"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . Error: " + t2
						}
					}
					if t2I, ok := errInfo["error_description"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . Description: " + t2
						}
					}
					if t2I, ok := errInfo["error_uri"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . More Info: " + t2
						}
					}
				}
			}
		}
		return tokens, fmt.Errorf("the POST request to the token endpoint %s returned an error status code. Status: %s%s", tokenEndpoint, resp.Status, getTokenError)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokens, fmt.Errorf("failed to read the response from the token endpoint %s . Error: %w", tokenEndpoint, err)
	}
	logrus.Debugf("GetTokensUsingAuthCode string(bodyBytes): %s", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return tokens, fmt.Errorf("failed to unmarshal the response from the token endpoint as json. Error: %w", err)
	}
	return tokens, nil
}
