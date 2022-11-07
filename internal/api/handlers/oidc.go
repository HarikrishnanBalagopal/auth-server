package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/types"
)

func GetOIDCInfo() types.OIDCInfo {
	return types.OIDCInfo{
		JwksURI:          common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetJwksEndpointPath(),
		TokenEndpoint:    common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetTokenEndpointPath(),
		UserinfoEndpoint: common.Config.CurrentHost + common.Config.AuthServerBasePath + common.GetUserInfoEndpointPath(),
	}
}

func HandleOIDCInfo(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleOIDCInfo start")
	defer logrus.Trace("HandleOIDCInfo end")
	oidcInfo := GetOIDCInfo()
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(oidcInfo); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleJwks(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleJwks start")
	defer logrus.Trace("HandleJwks end")
	keys, err := crypto.GetJwks()
	if err != nil {
		logrus.Errorf("failed to get the server jwks. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
