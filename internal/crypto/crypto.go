package crypto

import (
	"fmt"

	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

// Setup sets up the crypto and JWT related stuff.
func Setup() error {
	logrus.Trace("crypto.Setup start")
	defer logrus.Trace("crypto.Setup end")
	return TokensSetup()
}

// GetTokens gives the JWT access tokens.
func GetTokens(userId, clientId string) (types.Tokens, error) {
	accessToken, err := EncodeAccessToken(types.AccessToken{Id: userId}, clientId)
	if err != nil {
		return types.Tokens{}, fmt.Errorf("failed to encode the user info as an access token. Error: %w", err)
	}
	refreshToken, err := EncodeRefreshToken(types.RefreshToken{Id: userId}, clientId)
	if err != nil {
		return types.Tokens{}, fmt.Errorf("failed to encode the user info as a refresh token. Error: %w", err)
	}
	return types.Tokens{
		AccessToken:  accessToken,
		IdToken:      accessToken,
		RefreshToken: refreshToken,
	}, nil
}
