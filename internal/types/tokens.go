package types

import "github.com/golang-jwt/jwt/v4"

type AccessToken struct {
	Id string `json:"id"`
}

type RefreshToken struct {
	Id string `json:"id"`
}

type PermissionToken struct {
	ResourceId     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type RPT struct {
	PermissionToken
	ResourcePath string `json:"res_path"`
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Type    string `json:"custom-type"`
	Payload string `json:"custom-payload"`
	AZP     string `json:"azp"`
}
