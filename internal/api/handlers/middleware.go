package handlers

import (
	"context"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/sessions"
	"github.com/konveyor/auth-server/internal/types"
	_logrus "github.com/sirupsen/logrus"
)

type ctxKeyT string

const (
	requestIdKey ctxKeyT = "request-id"
	loggerKey    ctxKeyT = "logger"
)

var (
	authExceptions = []*regexp.Regexp{
		regexp.MustCompile(`^/support$`),
		regexp.MustCompile(`^/login$`),
		regexp.MustCompile(`^/login/callback$`),
		regexp.MustCompile(`^/logout$`),
		regexp.MustCompile(`^/user-login$`),
		regexp.MustCompile(`^/user-logout$`),
		regexp.MustCompile(`^/realms/[^/]+/\.well-known/openid-configuration$`),
		regexp.MustCompile(`^/realms/[^/]+/protocol/openid-connect/jwks$`),
		regexp.MustCompile(`^/realms/[^/]+/protocol/openid-connect/token$`),
		regexp.MustCompile(`^/realms/[^/]+/\.well-known/uma2-configuration$`),
	}
)

// GetRequestId returns the request id from the request's context
func GetRequestId(r *http.Request) string {
	return r.Context().Value(requestIdKey).(string)
}

// GetLogger returns the logger from the request's context
func GetLogger(r *http.Request) *_logrus.Entry {
	return r.Context().Value(loggerKey).(*_logrus.Entry)
}

// GetLoggingMiddleWare returns the middleware that logs each request method and URL
func GetLoggingMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestId := uuid.New().String()
		ctx = context.WithValue(ctx, requestIdKey, requestId)
		logger := _logrus.WithField("request-id", requestId)
		ctx = context.WithValue(ctx, loggerKey, logger)
		logger.Info(r.Method, " ", r.URL.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRemoveTrailingSlashMiddleWare returns the middleware that removes trailing slashes from the request URL
func GetRemoveTrailingSlashMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			r.URL.RawPath = strings.TrimSuffix(r.URL.RawPath, "/")
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}

// GetAuthorizationMiddleWare returns the middleware that checks for authorization
func GetAuthorizationMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus := GetLogger(r)
		logrus.Trace("AuthorizationMiddleWare start")
		defer logrus.Trace("AuthorizationMiddleWare end")
		resPath := strings.TrimPrefix(path.Clean(r.URL.Path), common.Config.AuthServerBasePath)
		logrus.Debugf("resPath: '%s'", resPath)
		if resPath == "" || resPath == "/" || resPath == "." {
			logrus.Warnf("after cleaning, the resPath is: '%s'", resPath)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		verb := r.Method
		logrus.Debugf("trying to access the resource at path '%s' with the verb '%s'", resPath, verb)
		// "/token" has its own authentication/authorization.
		// "/support" is general information about the deployment, useful for debugging.
		logrus.Debugf("authExceptions: %+v", authExceptions)
		if common.FindFunc(func(r *regexp.Regexp) bool { return r.MatchString(resPath) }, authExceptions) != -1 {
			logrus.Debugf("the resource '%s' and verb '%s' does not require authorization", resPath, verb)
			next.ServeHTTP(w, r)
			return
		}
		accessTokenStr := ""
		if authzHeader := r.Header.Get(common.AUTHZ_HEADER); authzHeader != "" {
			if !strings.HasPrefix(authzHeader, "Bearer ") {
				logrus.Debug("the authorization header is invalid. Expected: Bearer <access token> . Actual:", authzHeader)
				sendErrorJSON(w, "the authorization header is invalid", http.StatusBadRequest)
				return
			}
			accessTokenStr = strings.TrimPrefix(authzHeader, "Bearer ")
		} else {
			// if they didn't provide the access token, we check if they have an active sessInfo and get the token from the sessInfo
			sessInfo := sessions.GetSessionInfo(r)
			if sessInfo.Tokens.AccessToken == "" {
				logrus.Error("the user is not logged in. The session doesn't have any access token")
				w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// if err := sessInfo.RefreshUserTokensIfExpired(w, r); err != nil {
			// 	logrus.Errorf("the user's refresh token expired. Error: %q", err)
			// 	w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
			// 	w.WriteHeader(http.StatusUnauthorized)
			// 	return
			// }
			accessTokenStr = sessInfo.Tokens.AccessToken
			r.Header.Set(common.AUTHZ_HEADER, "Bearer "+accessTokenStr)
		}

		// resource server
		accessToken, err := crypto.DecodeAccessToken(accessTokenStr)
		if err != nil {
			logrus.Errorf("the user is not logged in. The access token is invalid. Error: %q", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		user, err := GetDB().ReadUser(accessToken.Id)
		if err != nil {
			logrus.Errorf("the user is not logged in. Failed to read the user with id '%s' . Error: %q", accessToken.Id, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := RBAC(user, resPath, verb); err != nil {
			logrus.Errorf("the user does not have permission to access the resource. Error: %q", err)
			sendErrorJSON(w, ErrNoAccess.Error(), http.StatusForbidden)
			return
		}

		logrus.Debugf("got authorization for user to access the protected resource")
		next.ServeHTTP(w, r)
	})
}

// GetCreateSessionMiddleWare returns the middleware that creates a session if it doesn't exist
func GetCreateSessionMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus := GetLogger(r)
		logrus.Trace("CreateSessionMiddleWare start ---------------------------------")
		defer logrus.Trace("CreateSessionMiddleWare end ---------------------------------")
		session, err := sessions.GetStore().Get(r, types.USER_SESSION_NAME)
		logrus.Debugf("got the session: %+v and error: %+v", session, err)
		if err == nil && !session.IsNew {
			next.ServeHTTP(w, r)
			return
		}
		logrus.Debugf("creating the new session: %+v", session)
		if err := sessions.ResetSession(session); err != nil {
			logrus.Errorf("failed to reset the newly created session. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logrus.Debugf("saving the new session: %+v", session)
		if err := sessions.GetStore().Save(r, w, session); err != nil {
			logrus.Errorf("failed to save the session. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s := session.Values[types.SESSION_KEY_SESSION_INFO].(types.SessionInfo)
		s.Id = session.ID
		session.Values[types.SESSION_KEY_SESSION_INFO] = s
		if err := sessions.GetStore().Save(r, w, session); err != nil {
			logrus.Errorf("failed to save the session. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
}
