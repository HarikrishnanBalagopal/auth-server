package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

const (
	NO_CONVERSION = "no_conversion"
)

func HandleRolesForUser(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleRolesForUser start")
	defer logrus.Trace("HandleRolesForUser end")
	vars := mux.Vars(r)
	userId, ok := vars["user-id"]
	if !ok {
		logrus.Errorf("the user id: '%s' is missing from the URL", userId)
		sendErrorJSON(w, "the user id: '%s' is missing from the URL", http.StatusNotFound)
		return
	}
	fs := GetDB()
	user, err := fs.ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to find the user with the id: '%s'", userId)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	roles := []types.GoCloakRole{}
	for _, roleId := range user.RoleIds {
		r, err := fs.ReadRole(roleId)
		if err != nil {
			logrus.Errorf("failed to read a role with the id: '%s' . Error: %q", roleId, err)
			continue
		}
		rp, err := r.ToAuthServerRole()
		if err != nil {
			logrus.Errorf("failed to convert the role %+v to a GoCloak role. Error: %q", r, err)
			continue
		}
		roles = append(roles, rp)
	}
	logrus.Debugf("roles: %+v", roles)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(roles); err != nil {
		logrus.Errorf("failed to encode the roles to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleListRoles(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleListRoles start")
	defer logrus.Trace("HandleListRoles end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	clientId, ok := vars["client-id"]
	if !ok {
		logrus.Errorf("the client id: '%s' is missing from the URL", clientId)
		sendErrorJSON(w, "the client id: '%s' is missing from the URL", http.StatusNotFound)
		return
	}
	logrus.Debugf("list all the roles under the namespace for the client '%s'", clientId)
	roles, err := GetDB().ListRoles(nil)
	if err != nil {
		logrus.Errorf("failed to list the roles for the client with id '%s' . Error: %q", clientId, err)
		sendErrorJSON(w, "failed to list roles for the client. Please recheck the access token", http.StatusForbidden)
		return
	}
	logrus.Debugf("listed roles before: %+v", roles)

	if r.URL.Query().Get(NO_CONVERSION) == "true" {
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(roles); err != nil {
			logrus.Errorf("failed to encode the roles (without conversion) to JSON and send the response. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	goRoles := []types.GoCloakRole{}
	for _, r := range roles {
		rp, err := r.ToAuthServerRole()
		if err != nil {
			logrus.Errorf("failed to convert the role '%+v' to an auth server role. Error: %q", r, err)
			continue
		}
		goRoles = append(goRoles, rp)
	}
	logrus.Debugf("roles after conversion, goRoles: %+v", goRoles)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(goRoles); err != nil {
		logrus.Errorf("failed to encode the roles to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateRole start")
	defer logrus.Trace("HandleCreateRole end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	role := types.Role{}
	if r.URL.Query().Get(NO_CONVERSION) == "true" {
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			logrus.Errorf("failed to decode the body as json. Error: %q", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		roleReq := types.GoCloakRole{}
		if err := json.NewDecoder(r.Body).Decode(&roleReq); err != nil {
			logrus.Errorf("failed to decode the body as json. Error: %q", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		role = types.FromAuthServerRole(roleReq)
	}

	for _, r := range role.Rules {
		for _, d := range r.Resources {
			if _, err := regexp.Compile(d); err != nil {
				logrus.Errorf("failed to compile the rule '%s' as a regex. Error: %q", d, err)
				sendErrorJSON(
					w,
					fmt.Sprintf("the rule '%s' is not a valid regex", d),
					http.StatusBadRequest,
				)
				return

			}
		}
		for _, v := range r.Verbs {
			if !isValidVerb(v) {
				s := fmt.Sprintf("invalid role, '%s' is not a valid verb", v)
				logrus.Errorf(s)
				sendErrorJSON(w, s, http.StatusBadRequest)
				return
			}
		}
	}

	logrus.Debugf("got a request to create the role: %+v", role)
	if err := GetDB().CreateRole(role); err != nil {
		logrus.Errorf("failed to create the role: %+v Error: %q", role, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": role.Id}); err != nil {
		logrus.Errorf("failed to send the response as json. Error: %q", err)
		return
	}
}

func HandleReadRole(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleReadRole start")
	defer logrus.Trace("HandleReadRole end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	clientId, ok := vars["client-id"]
	if !ok {
		logrus.Errorf("the client id is missing from the URL")
		sendErrorJSON(w, "the client id is missing from the URL", http.StatusNotFound)
		return
	}
	roleId, ok := vars["role-id"]
	if !ok {
		logrus.Errorf("the role id is missing from the URL")
		sendErrorJSON(w, "the role id is missing from the URL", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the role with id '%s' in the namespace for the client '%s'", roleId, clientId)
	role, err := GetDB().ReadRole(roleId)
	if err != nil {
		logrus.Errorf("failed to read the role with id '%s' . Error: %q", roleId, err)
		sendErrorJSON(w, "invalid role id", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the role: %+v", role)

	if r.URL.Query().Get(NO_CONVERSION) == "true" {
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(role); err != nil {
			logrus.Errorf("failed to encode the roles to JSON and send the response. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	convertedRole, err := role.ToAuthServerRole()
	if err != nil {
		logrus.Errorf("failed to convert the role '%+v' to an auth server role. Error: %q", r, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Debugf("the role after converting to a different format: %+v", convertedRole)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(convertedRole); err != nil {
		logrus.Errorf("failed to encode the roles to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUpdateRole start")
	defer logrus.Trace("HandleUpdateRole end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	role := types.Role{}
	if r.URL.Query().Get(NO_CONVERSION) == "true" {
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			logrus.Errorf("failed to decode the body as json. Error: %q", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		roleReq := types.GoCloakRole{}
		if err := json.NewDecoder(r.Body).Decode(&roleReq); err != nil {
			logrus.Errorf("failed to decode the body as json. Error: %q", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		role = types.FromAuthServerRole(roleReq)
	}

	for _, r := range role.Rules {
		for _, d := range r.Resources {
			if _, err := regexp.Compile(d); err != nil {
				logrus.Errorf("failed to compile the rule '%s' as a regex. Error: %q", d, err)
				sendErrorJSON(
					w,
					fmt.Sprintf("the rule '%s' is not a valid regex", d),
					http.StatusBadRequest,
				)
				return

			}
		}
		for _, v := range r.Verbs {
			if !isValidVerb(v) {
				s := fmt.Sprintf("invalid role, '%s' is not a valid verb", v)
				logrus.Errorf(s)
				sendErrorJSON(w, s, http.StatusBadRequest)
				return
			}
		}
	}

	oldRole, err := GetDB().ReadRole(role.Id)
	if err != nil {
		logrus.Errorf("failed to find the role. Error: %q", err)
		sendErrorJSON(w, "the role does not exist", http.StatusNotFound)
		return
	}
	role.Name = oldRole.Name
	role.Timestamp = oldRole.Timestamp
	role.Description = oldRole.Description

	logrus.Debugf("got a request to update the role: %+v", role)
	if err := GetDB().UpdateRole(role); err != nil {
		if !errors.Is(err, types.ErrNotFound) {
			logrus.Errorf("failed to update the role: %+v Error: %q", role, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logrus.Debugf("the role: %+v doesn't exist, trying to create it", role)
		if err := GetDB().CreateRole(role); err != nil {
			logrus.Errorf("failed to create the role: %+v Error: %q", role, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]string{"id": role.Id}); err != nil {
			logrus.Errorf("failed to send the response as json. Error: %q", err)
			return
		}
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusNoContent)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": role.Id}); err != nil {
		logrus.Errorf("failed to send the response as json. Error: %q", err)
		return
	}
}

func HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeleteRole start")
	defer logrus.Trace("HandleDeleteRole end")

	vars := mux.Vars(r)
	roleId, ok := vars["role-id"]
	if !ok {
		logrus.Errorf("the role id is missing from the URL")
		sendErrorJSON(w, "the role id is missing from the URL", http.StatusNotFound)
		return
	}
	if err := GetDB().DeleteRole(roleId); err != nil {
		logrus.Errorf("failed to delete the role with id '%s' from the database. Error: %q", roleId, err)
		if errors.Is(err, mux.ErrNotFound) {
			sendErrorJSON(
				w,
				fmt.Sprintf("failed to find the role with id '%s' in the database", roleId),
				http.StatusNotFound,
			)
			return
		}
		sendErrorJSON(
			w,
			fmt.Sprintf("failed to delete the role with id '%s' from the database", roleId),
			http.StatusBadRequest,
		)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func HandleDeleteRoles(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeleteRoles start")
	defer logrus.Trace("HandleDeleteRoles end")

	roleIds := []string{}
	if err := json.NewDecoder(r.Body).Decode(&roleIds); err != nil {
		logrus.Errorf("failed to unmarshal the request body to get role ids. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	for _, roleId := range roleIds {
		if err := GetDB().DeleteRole(roleId); err != nil {
			logrus.Errorf("failed to delete the role with id '%s' from the database. Error: %q", roleId, err)
			if errors.Is(err, mux.ErrNotFound) {
				sendErrorJSON(
					w,
					fmt.Sprintf("failed to find the role with id '%s' in the database", roleId),
					http.StatusNotFound,
				)
				return
			}
			sendErrorJSON(
				w,
				fmt.Sprintf("failed to delete the role with id '%s' from the database", roleId),
				http.StatusBadRequest,
			)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func HandleListRoleBindings(http.ResponseWriter, *http.Request) {

}

func HandlePatchRoleBindings(http.ResponseWriter, *http.Request) {

}

func HandleCreateRoleBinding(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateRoleBinding start")
	defer logrus.Trace("HandleCreateRoleBinding end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	userId, ok := vars["user-id"]
	if !ok {
		logrus.Errorf("the role id is missing from the URL")
		sendErrorJSON(w, "the role id is missing from the URL", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the user with id '%s'", userId)
	user, err := GetDB().ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to read the user with id '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the user: %+v", user)

	type ReqRole struct {
		Id string `json:"id"`
	}
	requestedRoleIds := []ReqRole{}
	if err := json.NewDecoder(r.Body).Decode(&requestedRoleIds); err != nil {
		logrus.Errorf("invalid body request, failed parse as json. Error: %q", err)
		sendErrorJSON(w, "invalid body request", http.StatusBadRequest)
		return
	}
	if len(requestedRoleIds) != 1 {
		logrus.Errorf("invalid request body, zero or too many role ids specified. actual: %+v", requestedRoleIds)
		sendErrorJSON(w, "invalid request body, exactly one role id expected", http.StatusBadRequest)
		return
	}
	logrus.Debugf("request body json. requestedRoleIds: %+v", requestedRoleIds)
	roleIds := common.Apply(func(x ReqRole) string {
		return x.Id
	}, requestedRoleIds)
	logrus.Debugf("request body json. roleIds: %+v", roleIds)
	if err := GetDB().AddOrRemoveRoles(userId, roleIds, true); err != nil {
		logrus.Errorf("failed to add roles to the user with id '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to add roles to the user", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func HandleDeleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteRoleBinding start")
	defer logrus.Trace("HandleDeleteRoleBinding end")
	if _, err := GetAccessTokenFromAuthzHeader(r); err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	userId, ok := vars["user-id"]
	if !ok {
		logrus.Errorf("the role id is missing from the URL")
		sendErrorJSON(w, "the role id is missing from the URL", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the user with id '%s'", userId)
	user, err := GetDB().ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to read the user with id '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	logrus.Debugf("read the user: %+v", user)

	type ReqRole struct {
		Id string `json:"id"`
	}
	requestedRoleIds := []ReqRole{}
	if err := json.NewDecoder(r.Body).Decode(&requestedRoleIds); err != nil {
		logrus.Errorf("invalid body request, failed parse as json. Error: %q", err)
		sendErrorJSON(w, "invalid body request", http.StatusBadRequest)
		return
	}
	if len(requestedRoleIds) != 1 {
		logrus.Errorf("invalid request body, zero or too many role ids specified. actual: %+v", requestedRoleIds)
		sendErrorJSON(w, "invalid request body, exactly one role id expected", http.StatusBadRequest)
		return
	}
	logrus.Debugf("request body json. requestedRoleIds: %+v", requestedRoleIds)
	roleIds := common.Apply(func(x ReqRole) string {
		return x.Id
	}, requestedRoleIds)
	logrus.Debugf("request body json. roleIds: %+v", roleIds)
	if err := GetDB().AddOrRemoveRoles(userId, roleIds, false); err != nil {
		logrus.Errorf("failed to add roles to the user with id '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to add roles to the user", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
