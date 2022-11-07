package handlers

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/sessions"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type TemplateData struct {
	UsernamePasswordLoginUrl string
	CsrfToken                string
	Idps                     []TemplateDataIdp
}

type TemplateDataIdp struct {
	Name     string
	LoginURL string
}

const (
	expectedResponseType = "code"
	expectedScope        = "openid profile email"
)

var (
	//go:embed templates/login.html
	_LOGIN_PAGE_TEMPLATE string
	// LOGIN_PAGE_TEMPLATE is the final parsed template of the login page
	LOGIN_PAGE_TEMPLATE = template.Must(template.New("").Parse(_LOGIN_PAGE_TEMPLATE))
)

// HandleLogin, Example:
// client_id=m2k-client&
// redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Flogin%2Fcallback&
// response_type=code&
// scope=openid+profile+email&
// state=9d3876ef3d766b576ccbfadc88068c8af5f520566d5eecc5aedbdde45cf23baf
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleLogin start")
	defer logrus.Trace("HandleLogin end")

	queryParams := r.URL.Query()

	logrus.Debug("check the client id against the list of registered clients")
	clientId := queryParams.Get("client_id")
	clientInfo, ok := common.Config.RegisteredClients[clientId]
	if !ok {
		logrus.Errorf("invalid client id. actual: %s", clientId)
		sendErrorJSON(w, "invalid client id", http.StatusUnauthorized)
		return
	}

	logrus.Debug("check the redirect url")
	redirectURL := queryParams.Get("redirect_uri")
	if common.Find(clientInfo.RedirectUrls, redirectURL) == -1 {
		logrus.Errorf("invalid redirect URL. actual: %s", redirectURL)
		sendErrorJSON(w, "invalid redirect URL", http.StatusBadRequest)
		return
	}

	logrus.Debug("check the response type")
	responseType := queryParams.Get("response_type")
	if responseType != expectedResponseType {
		logrus.Errorf("invalid response type. actual: %s", responseType)
		sendErrorJSON(w, "invalid response type", http.StatusBadRequest)
		return
	}

	logrus.Debug("check the requested scopes")
	scope := queryParams.Get("scope")
	if scope != expectedScope {
		logrus.Errorf("invalid scope. actual: %s", scope)
		sendErrorJSON(w, "invalid scope", http.StatusBadRequest)
		return
	}

	logrus.Debug("check the request state")
	state := queryParams.Get("state")
	if state == "" {
		logrus.Errorf("invalid state, state is empty")
		sendErrorJSON(w, "invalid state, state is empty", http.StatusBadRequest)
		return
	}

	logrus.Debug("check for configured identity providers")
	if len(common.Config.IdentityProviders) == 0 {
		logrus.Errorf("no identity providers configured")
		sendErrorJSON(w, "no identity providers configured", http.StatusInternalServerError)
		return
	}

	logrus.Debug("create a new cookie based session for the user to track the login process")
	sessInfo := sessions.GetSessionInfo(r)
	logrus.Debug("save the redirect url and state in the session so we can redirect the user after login")
	sessInfo.RedirectUrl = redirectURL
	sessInfo.PreviousState = state
	if err := sessions.SaveSessionInfo(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Debugf("new session id: %s", sessInfo.Id)

	templateData := TemplateData{
		UsernamePasswordLoginUrl: common.Config.AuthServerBasePath + common.LOGIN_CALLBACK_PATH,
	}
	csrfToken := sessInfo.GetCSRFToken()
	newRedirectUrl := GetLoginRedirectUrl()
	for _, idp := range common.Config.IdentityProviders {
		loginURL, err := url.Parse(idp.CollectedInfo.AuthorizationEndpoint)
		if err != nil {
			logrus.Errorf(
				"failed to parse the auth url '%s' for the idp with id '%s' . Error: %q",
				idp.CollectedInfo.AuthorizationEndpoint, idp.Id, err,
			)
			continue
		}
		newQueryParams := loginURL.Query()
		newQueryParams.Set("client_id", idp.ClientId)
		newQueryParams.Set("redirect_uri", newRedirectUrl)
		newQueryParams.Set("response_type", expectedResponseType)
		newQueryParams.Set("scope", expectedScope)
		newQueryParams.Set("state", idp.Id+"-"+csrfToken)
		loginURL.RawQuery = newQueryParams.Encode()
		templateData.Idps = append(templateData.Idps, TemplateDataIdp{
			Name:     idp.Id,
			LoginURL: loginURL.String(),
		})
	}

	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_HTML)
	w.WriteHeader(http.StatusOK)
	if err := LOGIN_PAGE_TEMPLATE.Execute(w, templateData); err != nil {
		logrus.Errorf("failed to create the login page. Error: %q", err)
		sendErrorJSON(w, "failed to generate the login page", http.StatusInternalServerError)
		return
	}
}

// HandleLoginCallback handles the last part of the OIDC login flow, Example:
// GET /auth-server/login/callback?
// code=91ptFv6wz84EoISW8QvMNDJoUsNPh7&
// grant_id=cef9e2d3-6ca3-4752-a655-926b7f2aaa7b&
// state=ibm-id-aea2a2c5e65db13fef079b9703be5daa37525fe6c68d5a0b44891060e64ef4d0
func HandleLoginCallback(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleLoginCallback start")
	defer logrus.Trace("HandleLoginCallback end")

	queryParams := r.URL.Query()

	logrus.Debug("check if the user is already logged in")
	if sessions.IsLoggedIn(r) {
		logrus.Error("the user is already logged in")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	logrus.Debug("validate the state/CSRF token")
	idpIdAndActualCSRFToken := queryParams.Get("state")
	if idpIdAndActualCSRFToken == "" {
		logrus.Errorf("invalid state, state is empty")
		sendErrorJSON(w, "invalid state, state is empty", http.StatusBadRequest)
		return
	}
	foundIDPId := ""
	for idpId := range common.Config.IdentityProviders {
		if strings.HasPrefix(idpIdAndActualCSRFToken, idpId+"-") {
			foundIDPId = idpId
			break
		}
	}
	if foundIDPId == "" {
		logrus.Errorf("no identity provider was found that matches the given state. actual: %s", idpIdAndActualCSRFToken)
		sendErrorJSON(w, "invalid state", http.StatusBadRequest)
		return
	}
	actualCSRFToken := strings.TrimPrefix(idpIdAndActualCSRFToken, foundIDPId+"-")
	if actualCSRFToken == "" {
		logrus.Errorf("invalid state, state is missing the CSRF token. actual: %s", idpIdAndActualCSRFToken)
		sendErrorJSON(w, "invalid state", http.StatusBadRequest)
		return
	}
	logrus.Debug("get the session that started the login process to check the CSRF token")
	sessInfo := sessions.GetSessionInfo(r)
	if !sessInfo.IsValidCSRFToken(actualCSRFToken) {
		logrus.Errorf("the CSRF token doesn't match")
		logrus.Debugf("Expected: %s Actual: %s", sessInfo.GetCSRFToken(), actualCSRFToken)
		sendErrorJSON(w, "invalid state", http.StatusBadRequest)
		return
	}

	logrus.Debug("check for errors returned by the authorization server")
	if authFlowError := queryParams.Get("error"); authFlowError != "" {
		if authFlowErrorDesc := queryParams.Get("error_description"); authFlowErrorDesc != "" {
			authFlowError = authFlowError + " . Description: " + authFlowErrorDesc
		}
		if authFlowErrorURL := queryParams.Get("error_uri"); authFlowErrorURL != "" {
			authFlowError = authFlowError + " . More Info: " + authFlowErrorURL
		}
		logrus.Errorf("user failed to authenticate or denied consent. Error: %q", authFlowError)
		sendErrorJSON(w, "user failed to authenticate or denied consent", http.StatusForbidden)
		return
	}

	logrus.Debug("get the authorization code")
	authCode := queryParams.Get("code")
	if authCode == "" {
		logrus.Error("invalid code, code is empty")
		sendErrorJSON(w, "invalid code", http.StatusBadRequest)
		return
	}

	logrus.Debug("get the access and refresh tokens using the authorization code")
	tokens, err := crypto.GetTokensUsingAuthCode(
		r.Context(),
		common.Config.IdentityProviders[foundIDPId],
		authCode,
		GetLoginRedirectUrl(),
	)
	if err != nil {
		logrus.Errorf("failed to get the tokens using the authorization code. Error: %q", err)
		sendErrorJSON(w, "failed to get tokens using the authorization code", http.StatusInternalServerError)
		return
	}
	sessInfo.Tokens = tokens

	logrus.Debug("get the user's profile information")
	userInfo, err := crypto.GetUserInfo(
		r.Context(),
		tokens.AccessToken,
		common.Config.IdentityProviders[foundIDPId],
	)
	if err != nil {
		logrus.Errorf("failed to get the user information from the authorization server. Error: %q", err)
		sendErrorJSON(w, "failed to get user info", http.StatusInternalServerError)
		return
	}
	logrus.Debug("log the user info for debugging purposes")
	logrus.Debugf("LoginCallback got the userInfo: %+v", userInfo)
	if userInfo.Sub != nil {
		logrus.Debugf("LoginCallback userInfo subject: %s", *userInfo.Sub)
	}
	if userInfo.PreferredUsername != nil {
		logrus.Debugf("LoginCallback userInfo preferred username: %s", *userInfo.PreferredUsername)
	}
	if userInfo.Email != nil {
		logrus.Debugf("LoginCallback userInfo email: %s", *userInfo.Email)
	}
	user, err := types.NewUserFromUserInfo(userInfo, false)
	if err != nil {
		logrus.Errorf("failed to create a new user object using the info %+v . Error: %q", userInfo, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sessInfo.User = user

	logrus.Debug("save the tokens and user information in the session information")
	if err := sessions.SaveSessionInfo(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session to the store. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logrus.Debug("create the redirect url to redirect the user to the original app")
	// code=EqApPx8YX3ZtL7RDRgSTS8lRYc504k&
	// grant_id=69b5b819-2dd9-42b0-b179-3b16be4e71d5&
	// state=ibm-id-0838e5a9bc60abe43bcf6ada720a01540feaf95df83485bcf5b6dcc873c4956d
	finalRedirectUrl, err := url.Parse(sessInfo.RedirectUrl)
	if err != nil {
		logrus.Errorf("failed to parse the app server login redirect URL. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newAuthCode := common.GetRandomString()
	newQueryParams := finalRedirectUrl.Query()
	newQueryParams.Set("code", newAuthCode)
	newQueryParams.Set("state", sessInfo.PreviousState)
	finalRedirectUrl.RawQuery = newQueryParams.Encode()
	fs := GetDB()
	if err := fs.SetAuthCodeToLoginData(
		newAuthCode,
		types.LoginData{
			IdpId:  foundIDPId,
			UserId: user.Id,
			Tokens: tokens,
		},
	); err != nil {
		logrus.Errorf("failed to save the auth code and user info to the database. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if existingUser, err := fs.ReadUser(user.Id); err != nil {
		if !errors.Is(err, types.ErrNotFound) {
			logrus.Errorf("failed to read the user with id '%s' in the database. Error: %q", user.Id, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user = common.AddDefaultRolesToUser(user)
		if err := fs.CreateUser(user); err != nil {
			logrus.Errorf("failed to save the user to the database. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		if existingUser.IsServiceAccount {
			logrus.Errorf("the user is trying to login with a service account")
			sendErrorJSON(
				w,
				"service accounts are not allowed to login. Please use the client id and secret to get an access token",
				http.StatusForbidden,
			)
			return
		}
	}

	logrus.Debug("redirect the user back to the app server where they started the login flow")
	http.Redirect(w, r, finalRedirectUrl.String(), http.StatusFound)
}

func HandleGetAccessToken(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetAccessToken start")
	defer logrus.Trace("HandleGetAccessToken end")

	logrus.Debug("check the authorization header")
	authHeader := r.Header.Get(common.AUTHZ_HEADER)
	if authHeader == "" {
		logrus.Error("invalid authorization header, header is empty")
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Basic" {
		logrus.Errorf("invalid authorization header. expected: 'Basic'. actual: %s", authHeader)
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	clientIdAndSecretBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		logrus.Errorf("invalid authorization header. Error: %q", err)
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	clientIdAndSecret := string(clientIdAndSecretBytes)
	clientIdAndSecretParts := strings.Split(clientIdAndSecret, ":")
	if len(clientIdAndSecretParts) != 2 {
		logrus.Errorf("invalid authorization header. actual: %s", authHeader)
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	clientId := clientIdAndSecretParts[0]
	clientSecret := clientIdAndSecretParts[1]

	logrus.Debug("check the client id and client secret")
	client, ok := common.Config.RegisteredClients[clientId]
	if !ok {
		logrus.Errorf("invalid authorization header. Did not find a client that matches the id. actual: '%s'", clientIdAndSecret)
		sendErrorJSON(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}
	if !common.ContantTimeEqual(clientSecret, client.Secret) {
		logrus.Errorf("invalid authorization header. The client secret doesn't match. actual: '%s'", clientIdAndSecret)
		sendErrorJSON(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}

	logrus.Debug("parse the request body to get the redirect URL and authorization code")
	if err := r.ParseForm(); err != nil {
		logrus.Errorf("failed to parse the request body as form url-encoded. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	logrus.Debugf("the request body form fields: %+v", r.Form)
	logrus.Debug("check the grant type")
	grantType := r.Form.Get("grant_type")
	if grantType != "authorization_code" && grantType != "client_credentials" && grantType != "refresh_token" {
		logrus.Errorf("invalid grant_type in the request body. actual: '%s'", grantType)
		sendErrorJSON(w, "invalid grant_type in the request body", http.StatusBadRequest)
		return
	}
	if grantType == "client_credentials" {
		tokens, err := crypto.GetTokens(client.Id, client.Id)
		if err != nil {
			logrus.Errorf("failed to get the tokens for the client: %+v . Error: %q", client, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(tokens); err != nil {
			logrus.Errorf("failed to encode the tokens to JSON and send the response. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}
	if grantType == "refresh_token" {
		logrus.Debug("refresh token grant type flow")
		logrus.Debug("checking the refresh token")
		refreshTokenStr := r.Form.Get("refresh_token")
		refreshToken, err := crypto.DecodeRefreshToken(refreshTokenStr)
		if err != nil {
			logrus.Errorf("invalid refresh token in the response body. Error: %q", err)
			sendErrorJSON(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		user, err := GetDB().ReadUser(refreshToken.Id)
		if err != nil {
			logrus.Errorf("failed to read the user from the database. Error: %q", err)
			sendErrorJSON(w, "failed to read the user from the database", http.StatusBadRequest)
			return
		}
		logrus.Debugf("found the user using the refresh token: %+v", user)

		tokens, err := crypto.GetTokens(user.Id, client.Id)
		if err != nil {
			logrus.Errorf("failed to get the tokens using user info: %+v . Error: %q", user.UserInfo, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(tokens); err != nil {
			logrus.Errorf("failed to encode the tokens to JSON and send the response. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}
	logrus.Debug("check the redirect URL")
	redirectUrl := r.Form.Get("redirect_uri")
	if redirectUrl == "" {
		logrus.Errorf("invalid redirect_uri, redirect_uri is empty")
		sendErrorJSON(w, "invalid redirect_uri, redirect_uri is empty", http.StatusBadRequest)
		return
	}
	if idx := common.Find(client.RedirectUrls, redirectUrl); idx == -1 {
		logrus.Errorf("invalid redirect url. actual: %s", redirectUrl)
		sendErrorJSON(w, "invalid redirect url", http.StatusUnauthorized)
		return
	}
	fs := GetDB()
	recvCode := r.Form.Get("code")
	data, err := fs.GetLoginDataFromAuthCode(recvCode)
	if err != nil {
		logrus.Errorf("invalid authorization code in the response body. Actual: '%s' Error: %q", recvCode, err)
		sendErrorJSON(w, "invalid authorization code", http.StatusBadRequest)
		return
	}
	user, err := fs.ReadUser(data.UserId)
	if err != nil {
		logrus.Errorf("failed to read the user from the database. Error: %q", err)
		sendErrorJSON(w, "failed to read the user from the database", http.StatusBadRequest)
		return
	}
	logrus.Debugf("found the user: %+v", user)

	tokens, err := crypto.GetTokens(user.Id, client.Id)
	if err != nil {
		logrus.Errorf("failed to get the tokens using user info: %+v . Error: %q", user.UserInfo, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logrus.Debug("save the tokens in the session so we can use it later")
	sessInfo := sessions.GetSessionInfo(r)
	sessInfo.Tokens = tokens
	if err := sessions.SaveSessionInfo(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		logrus.Errorf("failed to encode the tokens to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUserInfo start")
	defer logrus.Trace("HandleUserInfo end")

	authHeader := r.Header.Get(common.AUTHZ_HEADER)
	if authHeader == "" {
		logrus.Error("the authorization header is missing")
		sendErrorJSON(w, "the authorization header is missing", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		logrus.Errorf("invalid authorization header. actual: %s", authHeader)
		sendErrorJSON(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}
	accessTokenStr := parts[1]
	accessToken, err := crypto.DecodeAccessToken(accessTokenStr)
	if err != nil {
		logrus.Errorf("failed to decode the access token. Error: %q", err)
		sendErrorJSON(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	user, err := GetDB().ReadUser(accessToken.Id)
	if err != nil {
		logrus.Errorf("failed to find the user with id '%s' in the database. Error: %q", accessToken.Id, err)
		sendErrorJSON(w, "failed to find the user in the database", http.StatusNotFound)
		return
	}
	user.Password = nil
	logrus.Debugf("user: %+v", user)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logrus.Errorf("failed encode the user info as json and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleLogout start")
	defer logrus.Trace("HandleLogout end")
	if !sessions.IsLoggedIn(r) {
		logrus.Errorf("user is trying to log out without logging in")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := sessions.DeleteSession(w, r); err != nil {
		logrus.Errorf("failed to delete the session. Error: %q", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GetLoginRedirectPath returns the URL path to redirect to after the OIDC login flow ends (without the base path)
func GetLoginRedirectPath() string {
	if common.Config.AuthServerLoginRedirectUrl != "" {
		u, err := url.Parse(common.Config.AuthServerLoginRedirectUrl)
		if err != nil {
			panic(err)
		}
		return strings.TrimPrefix(u.Path, common.Config.AuthServerBasePath)
	}
	return common.LOGIN_CALLBACK_PATH
}

// GetLoginRedirectUrl returns the URL to redirect to after the OIDC login flow ends
func GetLoginRedirectUrl() string {
	if common.Config.AuthServerLoginRedirectUrl != "" {
		return common.Config.AuthServerLoginRedirectUrl
	}
	if common.Config.AuthServerLoginRedirectHost != "" {
		return common.Config.AuthServerLoginRedirectHost + common.Config.AuthServerBasePath + common.LOGIN_CALLBACK_PATH
	}
	return common.Config.CurrentHost + common.Config.AuthServerBasePath + common.LOGIN_CALLBACK_PATH
}

// HandleUsernamePasswordLogin handles login using username and password
func HandleUsernamePasswordLogin(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUsernamePasswordLogin start")
	defer logrus.Trace("HandleUsernamePasswordLogin end")

	logrus.Debug("check if the user is already logged in")
	if sessions.IsLoggedIn(r) {
		logrus.Error("the user is already logged in")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	sessInfo := sessions.GetSessionInfo(r)

	if r.Method == http.MethodGet {
		logrus.Debug("create and send a new csrf token")
		csrfToken := common.GetRandomString()
		sessInfo.CsrfToken = csrfToken
		if err := sessions.SaveSessionInfo(w, r, sessInfo); err != nil {
			logrus.Errorf("failed to save the session info with the new csrf token. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data := TemplateData{
			UsernamePasswordLoginUrl: common.Config.AuthServerBasePath + common.USERNAME_PASSWORD_LOGIN_PATH,
			CsrfToken:                csrfToken,
		}
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_HTML)
		w.WriteHeader(http.StatusOK)
		if err := LOGIN_PAGE_TEMPLATE.Execute(w, data); err != nil {
			logrus.Errorf("failed to execute the login page template with data %+v and send it to the response with. Error: %q", data, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	if sessInfo.CsrfToken == "" {
		logrus.Errorf("the session does not have a csrf token yet")
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		logrus.Errorf("failed to decode the request body. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	csrfToken := r.Form.Get("csrf_token")
	if username == "" || password == "" || csrfToken != sessInfo.CsrfToken {
		logrus.Errorf("invalid username, password and/or csrf_token. actual username '%s' password '%s' csrfToken '%s'", username, password, csrfToken)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	logrus.Debugf("trying to login using password and user id: '%s'", username)
	user, err := GetDB().ReadUser(username)
	if err != nil {
		logrus.Errorf("failed to find the user. Error: %q", err)
		sendErrorJSON(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if user.NumFailedAttempts >= common.Config.MaxLoginAttempts {
		logrus.Errorf("too many failed attempts to login")
		sendErrorJSON(w, "too many failed attempts to login", http.StatusBadRequest)
		return
	}
	if len(user.Password) == 0 {
		logrus.Errorf("the user does not have a password")
		sendErrorJSON(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
		logrus.Errorf("invalid password. Error: %q", err)
		user.NumFailedAttempts++
		logrus.Infof("number of failed login attempts: '%d'", user.NumFailedAttempts)
		if err := GetDB().UpdateUser(user); err != nil {
			logrus.Errorf("failed to update the num of failed login attempts for the user with id '%s' . Error: %q", user.Id, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sendErrorJSON(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	user.NumFailedAttempts = 0
	if err := GetDB().UpdateUser(user); err != nil {
		logrus.Errorf("failed to update the num of failed login attempts for the user with id '%s' . Error: %q", user.Id, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logrus.Debug("get the access and refresh tokens using the authorization code")
	tokens, err := crypto.GetTokens(username, types.AUTH_SERVER_UI_CLIENT_ID)
	if err != nil {
		logrus.Errorf("failed to get the tokens using the authorization code. Error: %q", err)
		sendErrorJSON(w, "failed to get tokens using the authorization code", http.StatusInternalServerError)
		return
	}
	sessInfo.Tokens = tokens
	sessInfo.User = user

	logrus.Debug("save the tokens and user information in the session information")
	if err := sessions.SaveSessionInfo(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session to the store. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Debug("the user logged in using username and password")
	// Send 303 See Other https://en.wikipedia.org/wiki/Post/Redirect/Get
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
