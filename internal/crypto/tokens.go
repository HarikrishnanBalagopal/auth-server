package crypto

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
)

var (
	// ssh-keygen -t ed25519 -C "your_email@example.com"
	// openssl genpkey -algorithm ed25519 -out private.pem
	// openssl pkey -in private.pem -pubout -out public.pem
	// openssl genrsa -out private-key.pem 4096
	// openssl rsa -in private-key.pem -pubout -out public-key.pem
	serverPrivateKey crypto.PrivateKey
	serverPublicKey  crypto.PublicKey
)

func GetJwks() (jwk.Set, error) {
	logrus.Trace("GetJwks start")
	defer logrus.Trace("GetJwks end")
	set := jwk.NewSet()
	logrus.Infof("loading the private key")
	pubKeyPem, ok := common.Config.ServerJwks["private"]
	if !ok {
		return set, fmt.Errorf("no private key configured")
	}
	pubKey, err := jwk.Parse([]byte(pubKeyPem), jwk.WithPEM(true))
	if err != nil {
		return set, err
	}
	logrus.Debugf("parsed the key. pubKey: %+v", pubKey)
	return pubKey, nil
}

func TokensSetup() error {
	logrus.Trace("crypto.TokensSetup start")
	defer logrus.Trace("crypto.TokensSetup end")

	logrus.Infof("loading the private key")
	privKeyPem, ok := common.Config.ServerJwks["private"]
	if !ok {
		return fmt.Errorf("no private key configured")
	}
	key, err := ParsePrivateKey([]byte(privKeyPem))
	if err != nil {
		return fmt.Errorf("failed to parse the private key. Error: %w", err)
	}
	serverPrivateKey = key

	logrus.Infof("loading the public key")
	pubKeyPem, ok := common.Config.ServerJwks["public"]
	if !ok {
		return fmt.Errorf("no public key configured")
	}
	pubKey, err := ParsePublicKey([]byte(pubKeyPem))
	if err != nil {
		return fmt.Errorf("failed to parse the public key. Error: %w", err)
	}
	serverPublicKey = pubKey
	return nil
}

func ParsePrivateKey(keyPemBytes []byte) (crypto.PrivateKey, error) {
	key, err := jwt.ParseEdPrivateKeyFromPEM(keyPemBytes)
	// key, err := jwt.ParseRSAPrivateKeyFromPEM(keyPemBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse the private key. Error: %w", err)
	}
	logrus.Debugf("private key: %T %+v", key, key)
	return key, nil
}

func ParsePublicKey(keyPemBytes []byte) (crypto.PublicKey, error) {
	key, err := jwt.ParseEdPublicKeyFromPEM(keyPemBytes)
	// key, err := jwt.ParseRSAPublicKeyFromPEM(keyPemBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse the public key. Error: %w", err)
	}
	logrus.Debugf("public key: %T %+v", key, key)
	return key, nil
}

func EncodeToken(key crypto.PrivateKey, claims types.CustomClaims, timeoutSeconds int64) (string, error) {
	logrus.Trace("EncodeToken start")
	defer logrus.Trace("EncodeToken end")
	issuedAt := time.Now()
	if timeoutSeconds <= 0 {
		timeoutSeconds = common.Config.AccessTokenTimeoutSeconds
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	claims.NotBefore = jwt.NewNumericDate(issuedAt)
	claims.ExpiresAt = jwt.NewNumericDate(issuedAt.Add(timeout))
	claims.Issuer = types.TokenIssuer
	claims.Audience = append(claims.Audience, types.TokenIssuer)
	if claims.Subject == "" {
		claims.Subject = types.TokenSubject
	}
	signedToken, err := jwt.NewWithClaims(new(jwt.SigningMethodEd25519), claims).SignedString(key)
	// signedToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
	if err != nil {
		return signedToken, fmt.Errorf("failed to sign the claims %+v with the private key. Error: %w", claims, err)
	}
	return signedToken, nil
}

func DecodeToken(key crypto.PublicKey, token string, audiences ...string) (types.CustomClaims, error) {
	parsed, err := jwt.ParseWithClaims(token, new(types.CustomClaims), func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != new(jwt.SigningMethodEd25519).Alg() {
			// if token.Method.Alg() != jwt.SigningMethodRS512.Alg() {
			return nil, fmt.Errorf("invalid signing method/alg. actual: %s", token.Method.Alg())
		}
		return key, nil
	})
	if err != nil {
		return types.CustomClaims{}, fmt.Errorf("failed to parse the token. Error: %w", err)
	}
	claims, ok := parsed.Claims.(*types.CustomClaims)
	if !ok || !parsed.Valid {
		return *claims, fmt.Errorf("token has invalid claims type. actual type is %T and value is %+v", parsed.Claims, parsed.Claims)
	}
	if err := parsed.Claims.Valid(); err != nil {
		return *claims, fmt.Errorf("the token is invalid. Error: %w", err)
	}
	now := time.Now()
	if !claims.VerifyExpiresAt(now, true) {
		return *claims, fmt.Errorf("token has invalid 'expires at'. actual: %+v", claims.ExpiresAt)
	}
	if !claims.VerifyNotBefore(now, true) {
		return *claims, fmt.Errorf("token has invalid 'not before'. actual: %+v", claims.NotBefore)
	}
	if !claims.VerifyIssuer(types.TokenIssuer, true) {
		return *claims, fmt.Errorf("token has invalid 'issuer'. actual: %+v", claims.Issuer)
	}
	if !claims.VerifyAudience(types.TokenIssuer, true) {
		return *claims, fmt.Errorf("token has invalid 'audience'. actual: %+v", claims.Audience)
	}
	for _, a := range audiences {
		if !claims.VerifyAudience(a, true) {
			return *claims, fmt.Errorf("did not find the audience '%s' in the token claims. actual: %+v", a, claims.Audience)
		}
	}
	return *claims, nil
}

func EncodeAccessToken(t types.AccessToken, audiences ...string) (string, error) {
	logrus.Debugf("EncodeAccessToken AccessToken %+v", t)
	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the token struct to json. Actual: %+v Error: %w", t, err)
	}
	claims := types.CustomClaims{
		Type:             types.TokenTypeAccess,
		Payload:          base64.StdEncoding.EncodeToString(payload),
		RegisteredClaims: jwt.RegisteredClaims{Subject: t.Id},
	}
	claims.Audience = append(claims.Audience, audiences...)
	if len(audiences) > 0 {
		claims.AZP = audiences[0]
	}
	logrus.Debugf("EncodeAccessToken claims %+v", claims)
	token, err := EncodeToken(serverPrivateKey, claims, 0)
	if err != nil {
		return "", fmt.Errorf("failed to encode the token claims. Actual: %+v Error: %w", claims, err)
	}
	return token, nil
}

func DecodeAccessToken(token string, audiences ...string) (types.AccessToken, error) {
	claims, err := DecodeToken(serverPublicKey, token, audiences...)
	if err != nil {
		return types.AccessToken{}, fmt.Errorf("failed to decode the token. Error: %w", err)
	}
	if claims.Type != types.TokenTypeAccess {
		return types.AccessToken{}, fmt.Errorf("invalid token type. Actual: '%s'", claims.Type)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		return types.AccessToken{}, fmt.Errorf("failed to decode the token payload as base64. Error: %w", err)
	}
	t := types.AccessToken{}
	if err := json.Unmarshal(payloadBytes, &t); err != nil {
		return t, fmt.Errorf("failed to unmarshal the token as json. Error: %w", err)
	}
	return t, nil
}

func EncodeRefreshToken(t types.RefreshToken, audiences ...string) (string, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the token struct to json. Actual: %+v Error: %w", t, err)
	}
	claims := types.CustomClaims{
		Type:             types.TokenTypeRefresh,
		Payload:          base64.StdEncoding.EncodeToString(payload),
		RegisteredClaims: jwt.RegisteredClaims{Subject: t.Id},
	}
	claims.Audience = append(claims.Audience, audiences...)
	if len(audiences) > 0 {
		claims.AZP = audiences[0]
	}
	token, err := EncodeToken(serverPrivateKey, claims, common.Config.RefreshTokenTimeoutSeconds)
	if err != nil {
		return "", fmt.Errorf("failed to encode the token claims. Actual: %+v Error: %w", claims, err)
	}
	return token, nil
}

func DecodeRefreshToken(token string, audiences ...string) (types.RefreshToken, error) {
	claims, err := DecodeToken(serverPublicKey, token, audiences...)
	if err != nil {
		return types.RefreshToken{}, fmt.Errorf("failed to decode the token. Error: %w", err)
	}
	if claims.Type != types.TokenTypeRefresh {
		return types.RefreshToken{}, fmt.Errorf("invalid token type. Actual: '%s'", claims.Type)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		return types.RefreshToken{}, fmt.Errorf("failed to decode the token payload as base64. Error: %w", err)
	}
	t := types.RefreshToken{}
	if err := json.Unmarshal(payloadBytes, &t); err != nil {
		return t, fmt.Errorf("failed to unmarshal the token as json. Error: %w", err)
	}
	return t, nil
}

func EncodePermissionToken(t types.PermissionToken, audiences ...string) (string, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the token struct to json. Actual: %+v Error: %w", t, err)
	}
	claims := types.CustomClaims{
		Type:    types.TokenTypePermission,
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
	claims.Audience = append(claims.Audience, audiences...)
	if len(audiences) > 0 {
		claims.AZP = audiences[0]
	}
	token, err := EncodeToken(serverPrivateKey, claims, 0)
	if err != nil {
		return "", fmt.Errorf("failed to encode the token claims. Actual: %+v Error: %w", claims, err)
	}
	return token, nil
}

func DecodePermissionToken(token string, audiences ...string) (types.PermissionToken, error) {
	claims, err := DecodeToken(serverPublicKey, token, audiences...)
	if err != nil {
		return types.PermissionToken{}, fmt.Errorf("failed to decode the token. Error: %w", err)
	}
	if claims.Type != types.TokenTypePermission {
		return types.PermissionToken{}, fmt.Errorf("invalid token type. Actual: '%s'", claims.Type)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		return types.PermissionToken{}, fmt.Errorf("failed to decode the token payload as base64. Error: %w", err)
	}
	t := types.PermissionToken{}
	if err := json.Unmarshal(payloadBytes, &t); err != nil {
		return t, fmt.Errorf("failed to unmarshal the token as json. Error: %w", err)
	}
	return t, nil
}

func EncodeRPToken(t types.RPT, audiences ...string) (string, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the token struct to json. Actual: %+v Error: %w", t, err)
	}
	claims := types.CustomClaims{
		Type:    types.TokenTypeRPT,
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
	claims.Audience = append(claims.Audience, audiences...)
	if len(audiences) > 0 {
		claims.AZP = audiences[0]
	}
	token, err := EncodeToken(serverPrivateKey, claims, 0)
	if err != nil {
		return "", fmt.Errorf("failed to encode the token claims. Actual: %+v Error: %w", claims, err)
	}
	return token, nil
}

func DecodeRPToken(token string, audiences ...string) (types.RPT, error) {
	claims, err := DecodeToken(serverPublicKey, token, audiences...)
	if err != nil {
		return types.RPT{}, fmt.Errorf("failed to decode the token. Error: %w", err)
	}
	if claims.Type != types.TokenTypeRPT {
		return types.RPT{}, fmt.Errorf("invalid token type. Actual: '%s'", claims.Type)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		return types.RPT{}, fmt.Errorf("failed to decode the token payload as base64. Error: %w", err)
	}
	t := types.RPT{}
	if err := json.Unmarshal(payloadBytes, &t); err != nil {
		return t, fmt.Errorf("failed to unmarshal the token as json. Error: %w", err)
	}
	return t, nil
}
