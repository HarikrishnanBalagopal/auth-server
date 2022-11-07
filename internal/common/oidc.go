package common

const (
	// REALM_PREFIX is the realms prefix for paths
	REALM_PREFIX = "/realms"
	// OIDC_API_V1_SUB_PATH is the sub path where the OIDC API is hosted
	OIDC_API_V1_SUB_PATH = "/protocol/openid-connect"
	// OIDC_API_V1_SUB_PATH = "/oidc/v1"
)

func GetOIDCBasePath() string {
	return REALM_PREFIX + "/" + Config.AuthServerRealm + OIDC_API_V1_SUB_PATH
}

func GetJwksEndpointPath() string {
	return GetOIDCBasePath() + "/jwks"
	// return OIDC_API_V1_SUB_PATH + "/endpoint/default/jwks"
}

func GetTokenEndpointPath() string {
	return GetOIDCBasePath() + "/token"
	// return OIDC_API_V1_SUB_PATH + "/endpoint/default/token"
}

func GetUserInfoEndpointPath() string {
	return GetOIDCBasePath() + "/userinfo"
	// return OIDC_API_V1_SUB_PATH + "/endpoint/default/userinfo"
}
