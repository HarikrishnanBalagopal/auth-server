package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

// GetUserInfo retrieves the user's information from the authz server, given the user's access token
func GetUserInfo(_ctx context.Context, accessToken string, idp types.IdentityProvider) (types.UserInfo, error) {
	logrus.Trace("GetUserInfo start")
	defer logrus.Trace("GetUserInfo end")
	ctx, cancel := context.WithTimeout(_ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", idp.CollectedInfo.UserinfoEndpoint, nil)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("failed to create the user info request. Error: %w", err)
	}
	req.Header.Set(common.AUTHZ_HEADER, "Bearer "+accessToken)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("failed to execute the user info request. Error: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return types.UserInfo{}, fmt.Errorf("got an error statuc code from the user info request. Error: %w", err)
	}
	defer resp.Body.Close()
	userInfo := types.UserInfo{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return userInfo, fmt.Errorf("failed to get the user profile from the authz server. Error: %w", err)
	}
	return userInfo, nil
}
