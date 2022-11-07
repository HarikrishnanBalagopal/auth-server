package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/konveyor/auth-server/internal/api/handlers"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// Serve starts the auth server.
func Serve() error {
	if err := handlers.Setup(); err != nil {
		return fmt.Errorf("failed to setup the handlers. Error: %w", err)
	}

	router := mux.NewRouter()
	router.Use(handlers.GetLoggingMiddleWare)

	logrus.Infof("putting all routes under the base path: '%s'", common.Config.AuthServerBasePath)
	baseRouter := router.PathPrefix(common.Config.AuthServerBasePath).Subrouter()
	baseRouter.Use(handlers.GetRemoveTrailingSlashMiddleWare)
	baseRouter.Use(handlers.GetCreateSessionMiddleWare)
	baseRouter.Use(handlers.GetAuthorizationMiddleWare)

	// dynamic routes
	baseRouter.HandleFunc("/support", handlers.HandleSupport).Methods("GET")

	// simple
	baseRouter.HandleFunc(common.USERNAME_PASSWORD_LOGIN_PATH, handlers.HandleUsernamePasswordLogin).Methods("GET")
	baseRouter.HandleFunc(common.USERNAME_PASSWORD_LOGIN_PATH, handlers.HandleUsernamePasswordLogin).Methods("POST")
	baseRouter.HandleFunc(common.USERNAME_PASSWORD_LOGOUT_PATH, handlers.HandleLogout).Methods("POST")

	// OIDC login
	baseRouter.HandleFunc(common.LOGIN_PATH, handlers.HandleLogin).Methods("GET")
	baseRouter.HandleFunc(common.LOGIN_CALLBACK_PATH, handlers.HandleLoginCallback).Methods("GET")
	baseRouter.HandleFunc(handlers.GetLoginRedirectPath(), handlers.HandleLoginCallback).Methods("GET")
	baseRouter.HandleFunc(common.LOGOUT_PATH, handlers.HandleLogout).Methods("POST")

	// OIDC endpoints
	baseRouter.HandleFunc("/realms/{realm-id}/.well-known/openid-configuration", handlers.HandleOIDCInfo).Methods("GET")
	baseRouter.HandleFunc(common.GetJwksEndpointPath(), handlers.HandleJwks).Methods("GET")
	baseRouter.HandleFunc(common.GetTokenEndpointPath(), handlers.HandleGetAccessToken).Methods("POST")
	baseRouter.HandleFunc(common.GetUserInfoEndpointPath(), handlers.HandleUserInfo).Methods("GET")

	// UMA
	baseRouter.HandleFunc("/realms/{realm-id}/.well-known/uma2-configuration", handlers.HandleUMAInfo).Methods("GET")
	baseRouter.HandleFunc(common.GetPermissionEndpointPath(), handlers.HandlePermissionTicket).Methods("POST")
	baseRouter.HandleFunc(common.GetRPTEndpointPath(), handlers.HandleRPT).Methods("POST")

	// admin routes
	{
		adminRouter := baseRouter.PathPrefix("/admin").Subrouter()
		// roles
		// m2k-test-client-id
		// ?briefRepresentation=false
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles", handlers.HandleListRoles).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles", handlers.HandleCreateRole).Methods("POST")
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles/{role-id}", handlers.HandleReadRole).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles/{role-id}", handlers.HandleUpdateRole).Methods("PUT")
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles/{role-id}", handlers.HandleDeleteRole).Methods("DELETE")
		adminRouter.HandleFunc("/realms/{realm-id}/clients/{client-id}/roles", handlers.HandleDeleteRoles).Methods("DELETE")
		adminRouter.HandleFunc("/realms/{realm-id}/clients", handlers.HandleGetClientWithFilters).Methods("GET")
		// ?briefRepresentation=false

		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}/role-mappings/clients/{client-id}/composite", handlers.HandleRolesForUser).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}/role-mappings/clients/{client-id}", handlers.HandleRolesForUser).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}/role-mappings/clients/{client-id}", handlers.HandleCreateRoleBinding).Methods("POST")
		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}/role-mappings/clients/{client-id}", handlers.HandleDeleteRoleBinding).Methods("DELETE")

		// users
		adminRouter.HandleFunc("/realms/{realm-id}/users", handlers.HandleGetUserWithFilters).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/users", handlers.HandleCreateUser).Methods("POST")
		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}", handlers.HandleReadUser).Methods("GET")
		adminRouter.HandleFunc("/realms/{realm-id}/users/{user-id}", handlers.HandleUpdateUser).Methods("PUT")
		adminRouter.HandleFunc("/realms/{realm-id}/users", handlers.HandleDeleteUsers).Methods("DELETE")
	}

	// static routes

	// auth server UI
	if staticFilesDir := common.Config.StaticFilesDir; staticFilesDir != "" {
		finfo, err := os.Stat(staticFilesDir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("the static files directory '%s' does not exist", staticFilesDir)
			}
			return fmt.Errorf("failed to stat the static files directory at path '%s' . Error: %q", staticFilesDir, err)
		}
		if !finfo.IsDir() {
			return fmt.Errorf("the path '%s' points to a file. Expected a directory containing static files to be served", staticFilesDir)
		}
		m2kUI := http.FileServer(http.Dir(staticFilesDir))
		letReactRouterHandleIt := func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != "GET" {
				return false
			}
			accepting := r.Header[common.ACCEPT_HEADER]
			if common.FindFunc(func(s string) bool { return strings.Contains(s, "text/html") }, accepting) == -1 {
				return false
			}
			w.Header().Set(common.CONTENT_TYPE_HEADER, "text/html")
			w.WriteHeader(http.StatusOK)
			http.ServeFile(w, r, filepath.Join(staticFilesDir, "index.html"))
			return true
		}
		// 404 not found handler for GET requests when static files are provided
		router.PathPrefix("/").Handler(handle404(m2kUI, letReactRouterHandleIt)).Methods("GET")
	}

	// 404 not found handler
	router.NotFoundHandler = router.NewRoute().HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.GetLogger(r).Errorf("%s %s - 404 Not Found", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}).GetHandler()

	logrus.Infof("Starting the auth server at port: %d", common.Config.Port)
	if common.Config.CertPath == "" && common.Config.KeyPath == "" {
		if err := http.ListenAndServe(":"+cast.ToString(common.Config.Port), router); err != nil {
			return fmt.Errorf("failed to listen and serve on port %d . Error: %w", common.Config.Port, err)
		}
	} else {
		if common.Config.CertPath == "" {
			return fmt.Errorf("HTTPS is enabled but the certificate file has not been provided")
		}
		if common.Config.KeyPath == "" {
			return fmt.Errorf("HTTPS is enabled but the private key file has not been provided")
		}
		if finfo, err := os.Stat(common.Config.CertPath); err != nil {
			return fmt.Errorf("failed to stat the certificate file at the path '%s' . Error: %w", common.Config.CertPath, err)
		} else if finfo.IsDir() {
			return fmt.Errorf("expected to find a certificate file at the path '%s'. Found a directory instead", common.Config.CertPath)
		}
		if finfo, err := os.Stat(common.Config.KeyPath); err != nil {
			return fmt.Errorf("failed to stat the private key file at the path '%s' . Error: %w", common.Config.KeyPath, err)
		} else if finfo.IsDir() {
			return fmt.Errorf("expected to find a private key file at the path '%s'. Found a directory instead", common.Config.KeyPath)
		}
		logrus.Info("HTTPS is enabled")
		if err := http.ListenAndServeTLS(":"+cast.ToString(common.Config.Port), common.Config.CertPath, common.Config.KeyPath, router); err != nil {
			return fmt.Errorf("failed to listen and serve using HTTPS on port %d . Error: %w", common.Config.Port, err)
		}
	}
	return nil
}

// let react router handle unrecognized text/html GET requests

type hijack404 struct {
	http.ResponseWriter
	R         *http.Request
	Handle404 func(w http.ResponseWriter, r *http.Request) bool
}

func (h *hijack404) WriteHeader(code int) {
	if code == 404 && h.Handle404(h.ResponseWriter, h.R) {
		panic(h)
	}
	h.ResponseWriter.WriteHeader(code)
}

func handle404(handler http.Handler, handle404 func(w http.ResponseWriter, r *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijack := &hijack404{ResponseWriter: w, R: r, Handle404: handle404}
		defer func() {
			if p := recover(); p != nil {
				if p == hijack {
					return
				}
				panic(p)
			}
		}()
		handler.ServeHTTP(hijack, r)
	})
}
