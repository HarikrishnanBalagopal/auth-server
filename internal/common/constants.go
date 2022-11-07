package common

import (
	"net/http"
	"regexp"

	"github.com/konveyor/auth-server/internal/types"
)

const (
	// SESSIONS_DIR is the name of the directory where the sessions are stored
	SESSIONS_DIR = "sessions"
	// LOGIN_PATH is the URL endpoint to start the login flow
	LOGIN_PATH = "/login"
	// LOGOUT_PATH is the URL endpoint to logout after logging in via the login flow
	LOGOUT_PATH = "/logout"
	// USERNAME_PASSWORD_LOGIN_PATH is the URL endpoint to login with username and password
	USERNAME_PASSWORD_LOGIN_PATH = "/user-login"
	// USERNAME_PASSWORD_LOGOUT_PATH is the URL endpoint to logout after logging in with username and password
	USERNAME_PASSWORD_LOGOUT_PATH = "/user-logout"
	// LOGIN_CALLBACK_PATH is the URL endpoint to finish the login flow
	LOGIN_CALLBACK_PATH = LOGIN_PATH + "/callback"
	// CONTENT_TYPE_HTML is the MIME type for html pages
	CONTENT_TYPE_HTML = "text/html"
	// CONTENT_TYPE_JSON is the MIME type for json body
	CONTENT_TYPE_JSON = "application/json"
	// CONTENT_TYPE_FORM_URL_ENCODED is the MIME type for URL encoded request bodies
	CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded"
	// CONTENT_TYPE_BINARY is the MIME type for binary body
	CONTENT_TYPE_BINARY = "application/octet-stream"
	// CONTENT_TYPE_CLOUD_EVENT is the MIME type for CloudEvents spec json body
	CONTENT_TYPE_CLOUD_EVENT = "application/cloudevents+json"
	// AUTHENTICATE_HEADER_MSG is the message returned in the authentication header
	AUTHENTICATE_HEADER_MSG = `Bearer realm="Access to the auth server API."`
	// OIDC_DISCOVERY_ENDPOINT_PATH is the OIDC discovery endpoint
	OIDC_DISCOVERY_ENDPOINT_PATH = "/realms/%s/.well-known/openid-configuration"
	// UMA_CONFIGURATION_ENDPOINT_PATH is the well known UMA endpoint
	UMA_CONFIGURATION_ENDPOINT_PATH = "/realms/%s/.well-known/uma2-configuration"
	// IDP_ID_ROUTE_VAR is the route variable for the identity provider id
	IDP_ID_ROUTE_VAR = "idp-id"
	// DELIM is the route variable for separating the identity provider id and the user id
	DELIM = "# $ #"
)

var (
	// Config contains the entire configuration for the API server
	Config types.ConfigT
	// ID_REGEXP is the regexp used to check if a Id is valid
	ID_REGEXP = regexp.MustCompile("^[a-zA-Z0-9-_]+$")
	// INVALID_NAME_CHARS_REGEXP is the regexp used to replace invalid name characters with hyphen
	INVALID_NAME_CHARS_REGEXP = regexp.MustCompile("[^a-z0-9-]")
	// ACCEPT_HEADER is the accept header
	ACCEPT_HEADER = http.CanonicalHeaderKey("Accept")
	// AUTHZ_HEADER is the authorization header
	AUTHZ_HEADER = http.CanonicalHeaderKey("Authorization")
	// AUTHENTICATE_HEADER is the authentication header
	AUTHENTICATE_HEADER = http.CanonicalHeaderKey("WWW-Authenticate")
	// CONTENT_TYPE_HEADER is the content type header
	CONTENT_TYPE_HEADER = http.CanonicalHeaderKey("Content-Type")
	// LOCATION_HEADER is the location header
	LOCATION_HEADER = http.CanonicalHeaderKey("Location")
)
