package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/spf13/cast"
)

func HandleGetClientWithFilters(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetClientWithFilters start")
	defer logrus.Trace("HandleGetClientWithFilters end")
	if err := r.ParseForm(); err != nil {
		logrus.Errorf("failed to parse the form. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	clientId := r.Form.Get("clientId")
	if clientId == "" {
		logrus.Errorf("clientId missing from request body")
		sendErrorJSON(w, "clientId missing from request body", http.StatusBadRequest)
		return
	}
	client, ok := common.Config.RegisteredClients[clientId]
	if !ok {
		logrus.Errorf("failed to find the client with the id: '%s'", clientId)
		sendErrorJSON(w, "failed to find the client", http.StatusNotFound)
		return
	}
	client.Secret = ""
	logrus.Debugf("send the client: %+v in the response", client)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode([]types.RegisteredClient{client}); err != nil {
		logrus.Errorf("failed to encode the user to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleGetUserWithFilters(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetUserWithFilters start")
	defer logrus.Trace("HandleGetUserWithFilters end")
	if err := r.ParseForm(); err != nil {
		logrus.Errorf("failed to parse the form. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	userId := r.Form.Get("username")
	if userId == "" {
		logrus.Debugf("'username' is missing from the request body, listing all users")
		users, err := GetDB().ListUsers(nil)
		if err != nil {
			logrus.Errorf("failed to list all the users. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logrus.Debugf("all users: %+v", users)
		for i := range users {
			users[i].Password = nil
		}
		logrus.Debugf("all users: %+v", users)
		w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(users); err != nil {
			logrus.Errorf("failed to encode the users to JSON and send the response. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	user, err := GetDB().ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to find the user with the id: '%s'", userId)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	logrus.Debugf("user after filtering by id: %+v", user)
	user.Password = nil
	logrus.Debugf("user after filtering by id: %+v", user)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode([]types.User{user}); err != nil {
		logrus.Errorf("failed to encode the user to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateUser start")
	defer logrus.Trace("HandleCreateUser end")
	userReq := types.ConfigUser{}
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		logrus.Errorf("failed to parse the request body as json. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	logrus.Debugf("request to create the userReq: %+v", userReq)
	if userReq.Email == "" {
		logrus.Errorf("email is missing from the request body")
		sendErrorJSON(w, "email is missing from the request body", http.StatusBadRequest)
		return
	}
	user, err := types.NewUser(userReq.Email, userReq.Email, userReq.IsServiceAccount, userReq.Password)
	if err != nil {
		logrus.Errorf("failed to create the new user object. Error: %q", err)
		if errors.Is(err, types.ErrServiceAccountWithPassword) {
			sendErrorJSON(w, fmt.Sprintf("invalid request body, %s", err.Error()), http.StatusBadRequest)
			return
		}
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	db := GetDB()
	for _, r := range userReq.RoleIds {
		if _, err := db.ReadRole(r); err != nil {
			logrus.Errorf("failed to find the role with the id: '%s' . Error: %q", r, err)
			sendErrorJSON(w, fmt.Sprintf("failed to find the role with the id: '%s'", r), http.StatusNotFound)
			return
		}
	}
	user.RoleIds = userReq.RoleIds
	user = common.AddDefaultRolesToUser(user)
	if err := db.CreateUser(user); err != nil {
		logrus.Errorf("failed to create the user: %+v Error: %q", user, err)
		if errors.Is(err, types.ErrAlreadyExist) {
			sendErrorJSON(w, fmt.Sprintf("failed to create the user, the id '%s' already exists", user.Id), http.StatusConflict)
			return
		}
		sendErrorJSON(w, "failed to create the user", http.StatusBadRequest)
		return
	}
	user.Password = nil
	logrus.Debugf("created the user: %+v", user)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.Header().Set(common.LOCATION_HEADER, "/realms/"+common.Config.AuthServerRealm+"/users/"+user.Id)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logrus.Errorf("failed to encode the user to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleReadUser(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetUser start")
	defer logrus.Trace("HandleGetUser end")
	vars := mux.Vars(r)
	userId, ok := vars["user-id"]
	if !ok {
		logrus.Errorf("the user id is missing from the URL")
		sendErrorJSON(w, "the user id is missing from the URL", http.StatusNotFound)
		return
	}
	user, err := GetDB().ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to find the user with the id: '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	user.Password = nil
	logrus.Debugf("send the user: %+v in the response", user)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logrus.Errorf("failed to encode the user to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUpdateUser start")
	defer logrus.Trace("HandleUpdateUser end")
	vars := mux.Vars(r)
	userId, ok := vars["user-id"]
	if !ok {
		logrus.Errorf("the user id is missing from the URL")
		sendErrorJSON(w, "the user id is missing from the URL", http.StatusNotFound)
		return
	}
	userReq := types.ConfigUser{}
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		logrus.Errorf("failed to parse the request body as json. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	logrus.Debugf("request to update the userReq: %+v", userReq)
	if userReq.Email == "" {
		logrus.Errorf("email is missing from the request body")
		sendErrorJSON(w, "email is missing from the request body", http.StatusBadRequest)
		return
	}
	db := GetDB()
	user, err := db.ReadUser(userId)
	if err != nil {
		logrus.Errorf("failed to find the user with the id: '%s' . Error: %q", userId, err)
		sendErrorJSON(w, "failed to find the user", http.StatusNotFound)
		return
	}
	user.UpdatedAt = cast.ToString(time.Now().Unix())
	user.Email = &userReq.Email
	user.IsServiceAccount = userReq.IsServiceAccount
	if user.IsServiceAccount {
		user.Password = nil
	}
	for _, r := range userReq.RoleIds {
		if _, err := db.ReadRole(r); err != nil {
			logrus.Errorf("failed to find the role with the id: '%s' . Error: %q", r, err)
			sendErrorJSON(w, fmt.Sprintf("failed to find the role with the id: '%s'", r), http.StatusNotFound)
			return
		}
	}
	user.RoleIds = userReq.RoleIds
	if err := db.UpdateUser(user); err != nil {
		logrus.Errorf("failed to update the user: %+v Error: %q", user, err)
		sendErrorJSON(w, "failed to update the user", http.StatusBadRequest)
		return
	}
	user.Password = nil
	logrus.Debugf("updated the user: %+v", user)
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.Header().Set(common.LOCATION_HEADER, "/realms/"+common.Config.AuthServerRealm+"/users/"+user.Id)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logrus.Errorf("failed to encode the user to JSON and send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleDeleteUsers(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteUsers start")
	defer logrus.Trace("HandleDeleteUsers end")

	reqIds := []string{}
	if err := json.NewDecoder(r.Body).Decode(&reqIds); err != nil {
		logrus.Errorf("failed to unmarshal the body as json. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	for _, id := range reqIds {
		if err := GetDB().DeleteUser(id); err != nil {
			logrus.Errorf("failed to delete the user with id '%s'. Error: %q", id, err)
			sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
