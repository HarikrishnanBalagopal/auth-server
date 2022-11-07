package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

const (
	defaultClaimTokenFormat = "urn:ietf:params:oauth:token-type:jwt"
)

var (
	ErrNoAccess    = fmt.Errorf("does not have permission to access this resource")
	ErrInvalidVerb = fmt.Errorf("invalid verb")
)

func GetUMAnfo() types.UMAInfo {
	return types.UMAInfo{
		JwksURI:            common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetJwksEndpointPath(),
		PermissionEndpoint: common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetPermissionEndpointPath(),
		TokenEndpoint:      common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetRPTEndpointPath(),
	}
}

func HandleUMAInfo(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUMAInfo start")
	defer logrus.Trace("HandleUMAInfo end")
	umaInfo := GetUMAnfo()
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(umaInfo); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandlePermissionTicket(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandlePermissionTicket start")
	defer logrus.Trace("HandlePermissionTicket end")
	permReqs := []types.PermissionToken{}
	if err := json.NewDecoder(r.Body).Decode(&permReqs); err != nil {
		logrus.Errorf("invalid request body, failed to unmarshal the request body as json. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(permReqs) != 1 {
		logrus.Errorf("expected there to be exactly one permissions request. Actual length: %d value: %+v", len(permReqs), permReqs)
		sendErrorJSON(w, "expected there to be exactly one permissions request", http.StatusBadRequest)
		return
	}
	logrus.Debugf("got the permission ticket request: %+v", permReqs)
	ticket, err := crypto.EncodePermissionToken(permReqs[0])
	if err != nil {
		logrus.Errorf("failed to create the permission ticket. Error: %q", err)
		sendErrorJSON(w, "invalid permissions request", http.StatusBadRequest)
		return
	}
	permTicket := types.PermTicket{Ticket: ticket}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(permTicket); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleRPT(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleRPT start")
	defer logrus.Trace("HandleRPT end")

	logrus.Debug("check the authorization header")
	authHeader := r.Header.Get(common.AUTHZ_HEADER)
	if authHeader == "" {
		logrus.Error("invalid authorization header, header is empty")
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		logrus.Errorf("invalid authorization header. expected: 'Bearer'. actual: %s", authHeader)
		sendErrorJSON(w, "invalid authorization header", http.StatusBadRequest)
		return
	}
	accessTokenStr := parts[1]
	accessToken, err := crypto.DecodeAccessToken(accessTokenStr)
	if err != nil {
		logrus.Errorf("invalid access token. Error: %q", err)
		sendErrorJSON(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	user, err := GetDB().ReadUser(accessToken.Id)
	if err != nil {
		logrus.Errorf("failed to read the user with id '%s' . Error: %q", accessToken.Id, err)
		sendErrorJSON(w, "invalid user id", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		logrus.Errorf("failed to parse the request body as form url-encoded. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	logrus.Debugf("the request body form fields: %+v", r.Form)
	logrus.Debug("check the grant type")
	grantType := r.Form.Get("grant_type")
	if grantType != types.UMA_GRANT_TYPE {
		logrus.Errorf("invalid grant_type in the response body. Expected: '%s' Actual: '%s'", types.UMA_GRANT_TYPE, grantType)
		sendErrorJSON(w, "invalid grant_type in the response body", http.StatusBadRequest)
		return
	}

	logrus.Debug("check the permission ticket")
	permTicketStr := r.Form.Get("ticket")
	if permTicketStr == "" {
		logrus.Error("invalid permission ticket, permission ticket is empty")
		sendErrorJSON(w, "invalid permission ticket", http.StatusBadRequest)
		return
	}
	permReq, err := crypto.DecodePermissionToken(permTicketStr)
	if err != nil {
		logrus.Errorf("failed to decode the permission ticket. Error: %q", err)
		sendErrorJSON(w, "invalid permission ticket", http.StatusBadRequest)
		return
	}

	logrus.Debug("check the authorization policies to decide if the user should be given a RPT for the permissions requested")
	if permReq.ResourceId != common.Config.DefaultResourceId {
		logrus.Errorf("invalid permission ticket, the resource id is invalid. Expected: '%s' Actual: '%s'", common.Config.DefaultResourceId, permReq.ResourceId)
		sendErrorJSON(w, "invalid resource id", http.StatusForbidden)
		return
	}

	logrus.Debug("checking against the RBAC authorization policies")
	if claimTokenFormat := r.Form.Get("claim_token_format"); claimTokenFormat != defaultClaimTokenFormat {
		logrus.Errorf("invalid permission ticket, the claim token format is invalid. Expected: '%s' Actual: '%s'", defaultClaimTokenFormat, claimTokenFormat)
		sendErrorJSON(w, "invalid claim token format", http.StatusForbidden)
		return
	}
	claimToken := r.Form.Get("claim_token")
	resPath, err := decodeClaimToken(claimToken)
	if err != nil {
		logrus.Errorf("failed to decode the claim token. Error: %q", err)
		sendErrorJSON(w, "invalid claim token", http.StatusForbidden)
		return
	}
	if len(permReq.ResourceScopes) != 1 {
		logrus.Errorf("invalid permission ticket, the resource scopes are invalid. Actual: %+v", permReq.ResourceScopes)
		sendErrorJSON(w, "invalid resource scopes", http.StatusForbidden)
		return
	}
	verb := permReq.ResourceScopes[0]
	if err := RBAC(user, resPath, verb); err != nil {
		logrus.Errorf("the user does not have permission to access the resource '%s' with the verb '%s' . Error: %q", resPath, verb, err)
		sendErrorJSON(w, ErrNoAccess.Error(), http.StatusForbidden)
		return
	}
	requestingPartyToken, err := crypto.EncodeRPToken(types.RPT{PermissionToken: permReq, ResourcePath: resPath})
	if err != nil {
		logrus.Errorf("failed to create the RPT. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokens := types.Tokens{AccessToken: requestingPartyToken}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		logrus.Errorf("failed to marshal the RPT to json and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func decodeClaimToken(token string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	x := map[string][]string{}
	if err := json.Unmarshal(b, &x); err != nil {
		return "", err
	}
	resPaths, ok := x["resource_path"]
	if !ok {
		return "", fmt.Errorf("failed to find the key 'resource_path' in the claim token. actual: %+v", x)
	}
	if len(resPaths) != 1 {
		return "", fmt.Errorf("expected exactly one value under the key 'resource_path'. actual: %+v", x)
	}
	return resPaths[0], nil
}

func RBAC(user types.User, resPath string, verb string) error {
	logrus.Trace("RBAC start ****************")
	defer logrus.Trace("RBAC end ****************")
	logrus.Debugf("resource '%s' verb '%s' user: %+v", resPath, verb, user)
	if !isValidHttpMethod(verb) {
		return ErrInvalidVerb
	}
	for _, roleId := range user.RoleIds {
		role, err := GetDB().ReadRole(roleId)
		if err != nil {
			return fmt.Errorf("failed to read the role with id '%s' . Error: %w", roleId, err)
		}
		logrus.Debugf("role: %+v", role)
		for _, rule := range role.Rules {
			logrus.Debugf("rule: %+v", rule)
			if idx := common.FindFunc(func(res string) bool {
				if res == resPath {
					return true
				}
				r, err := regexp.Compile(res)
				if err != nil {
					logrus.Errorf("failed to compile '%s' as a path regex. Error: %w", res, err)
					return false
				}
				return r.MatchString(resPath)
			}, rule.Resources); idx == -1 {
				continue
			}
			logrus.Debugf("the rule matched the resource path")
			if idx := common.Find(rule.Verbs, types.VERB_ALL_PERMS); idx != -1 {
				return nil
			}
			if idx := common.Find(rule.Verbs, verb); idx != -1 {
				return nil
			}
			logrus.Debugf("the verb is not allowed for the resource by this rule")
		}
	}
	return ErrNoAccess
}

// isValidVerb checks if it is a valid HTTP method
func isValidHttpMethod(verb string) bool {
	return verb == "GET" || verb == "POST" || verb == "PUT" || verb == "DELETE" || verb == "PATCH"
}

// isValidVerb checks if it is a valid verb to use in the list of role rules
func isValidVerb(verb string) bool {
	return isValidHttpMethod(verb) || verb == types.VERB_ALL_PERMS
}
