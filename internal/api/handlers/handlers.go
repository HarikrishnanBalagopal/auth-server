package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/database"
	"github.com/konveyor/auth-server/internal/sessions"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

const (
	// WORKSPACE_ID_ROUTE_VAR is the route variable that contains the workspace Id
	WORKSPACE_ID_ROUTE_VAR = "work-id"
	// PROJECT_ID_ROUTE_VAR is the route variable that contains the project Id
	PROJECT_ID_ROUTE_VAR = "proj-id"
	// PROJECT_INPUT_ID_ROUTE_VAR is the route variable that contains the project input Id
	PROJECT_INPUT_ID_ROUTE_VAR = "input-id"
	// PROJECT_OUTPUT_ID_ROUTE_VAR is the route variable that contains the project output Id
	PROJECT_OUTPUT_ID_ROUTE_VAR = "output-id"
	// ROLE_ID_ROUTE_VAR is the route variable that contains the role Id
	ROLE_ID_ROUTE_VAR = "role-id"
	// IDP_USER_ID_ROUTE_VAR is the route variable for the user id
	IDP_USER_ID_ROUTE_VAR = "user-id"
)

var (
	__db database.IDatabase
)

func GetDB() database.IDatabase {
	return __db
}

func SetDB(db database.IDatabase) {
	__db = db
}

// Setup handlers
func Setup() error {
	logrus.Trace("handlers.Setup start")
	defer logrus.Trace("handlers.Setup end")
	authExceptions = append(authExceptions, regexp.MustCompile(`^`+GetLoginRedirectPath()+`$`))
	if len(common.Config.ServerJwks) == 0 {
		return fmt.Errorf("the server keys have not been configured")
	}
	absDataDir, err := filepath.Abs(common.Config.DataDir)
	if err != nil {
		return fmt.Errorf("failed to make the data directory path '%s' absolute. Error: %w", common.Config.DataDir, err)
	}
	common.Config.DataDir = absDataDir
	logrus.Debug("creating the filesystem object")
	db, err := database.NewDatabase()
	if err != nil {
		return fmt.Errorf("failed to setup the database. Error: %w", err)
	}
	SetDB(db)
	if err := crypto.Setup(); err != nil {
		return fmt.Errorf("failed to setup the OIDC info. Error: %w", err)
	}
	if err := sessions.SetupSessionStore(); err != nil {
		return fmt.Errorf("failed to setup the session store. Error: %w", err)
	}
	logrus.Debug("looking for configured identity providers")
	for _, idp := range common.Config.IdentityProviders {
		logrus.Infof("collecting OIDC info for the IDP: %s", idp.Id)
		r, err := http.Get(idp.OIDCDiscoveryEndpoint)
		if err != nil {
			logrus.Errorf("failed to get the OIDC info for the identity provider: %+v . Error: %q", idp, err)
			continue
		}
		if r.StatusCode < 200 || r.StatusCode > 299 {
			logrus.Errorf("failed to get the OIDC info for the identity provider: %+v . Got an error status code: %s", idp, r.Status)
			continue
		}
		defer r.Body.Close()
		oidcInfo := types.OIDCInfo{}
		if err := json.NewDecoder(r.Body).Decode(&oidcInfo); err != nil {
			logrus.Errorf("failed to parse the OIDC info for the identity provider: %+v as JSON. Error: %q", idp, err)
			continue
		}
		idp.CollectedInfo = oidcInfo
		common.Config.IdentityProviders[idp.Id] = idp
		logrus.Infof("collected the following OIDC info: %+v", oidcInfo)
	}
	return nil
}

// HandleSupport is the handler for getting support information
func HandleSupport(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleSupport start")
	defer logrus.Trace("HandleSupport end")
	supportInfo := GetDB().GetSupportInfo()
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(supportInfo); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func sendErrorJSON(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(statusCode)
	errMsg := map[string]interface{}{"error": map[string]string{"description": message}}
	if common.Config.StringErrors {
		errMsg = map[string]interface{}{"error": message}
	}
	errBytes, err := json.Marshal(errMsg)
	if err != nil {
		logrus.Errorf("failed to marshal the error message to json. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(errBytes); err != nil {
		logrus.Errorf("failed to write the error message to the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// GetAccessTokenFromAuthzHeader returns the access token from the authorization bearer HTTP header
func GetAccessTokenFromAuthzHeader(r *http.Request) (string, error) {
	authzHeader := r.Header.Get(common.AUTHZ_HEADER)
	if authzHeader == "" {
		return "", fmt.Errorf("the Authorization header is missing")
	}
	if !strings.HasPrefix(authzHeader, "Bearer ") {
		return "", fmt.Errorf("expected `Bearer <access token>` in the Authorization header. Actual: %s", authzHeader)
	}
	return strings.TrimPrefix(authzHeader, "Bearer "), nil
}
