package types

const (
	TokenTypeIdentity   = "identity"
	TokenTypeAccess     = "access"
	TokenTypeRefresh    = "refresh"
	TokenTypePermission = "permission"
	TokenTypeRPT        = "rpt"

	TokenIssuer  = "auth-server"
	TokenSubject = "auth-client"
)

const (
	// APP_NAME stores the application name
	APP_NAME = "auth"
	// APP_NAME_SHORT stores the application shortname
	APP_NAME_SHORT = APP_NAME
	// USER_SESSION_NAME is the name of the cookie containing the user session id
	USER_SESSION_NAME = APP_NAME_SHORT + "-user"
	// SESSION_KEY_SESSION_INFO is the key used to store the session struct in the session store
	SESSION_KEY_SESSION_INFO = "session-info"
	// VERB_ALL_PERMS is the verb that allows all actions on the resource
	VERB_ALL_PERMS = "all"
	// AUTH_SERVER_UI_CLIENT_ID is the client id for the auth server's UI
	AUTH_SERVER_UI_CLIENT_ID = "auth-server-ui"
)
