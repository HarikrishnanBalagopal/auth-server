/*
Copyright IBM Corporation 2021

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/sessions"
	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/crypto"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

var (
	__sessionStore *sessions.FilesystemStore
)

func GetStore() *sessions.FilesystemStore {
	return __sessionStore
}

func SetStore(s *sessions.FilesystemStore) {
	__sessionStore = s
}

// SetupSessionStore sets up the session store.
func SetupSessionStore() error {
	logrus.Trace("SetupSessionStore start")
	defer logrus.Trace("SetupSessionStore end")
	sessionsDir := filepath.Join(common.Config.DataDir, common.SESSIONS_DIR)
	if err := os.MkdirAll(sessionsDir, 0777); err != nil {
		return fmt.Errorf("failed to create the directory at path %s Error: %w", sessionsDir, err)
	}
	gob.Register(types.SessionInfo{}) // required for serializing to session store.
	sessionSecret := common.Config.SessionSecret
	if sessionSecret == "" {
		logrus.Debug("no session secret specified. Generating a new one...")
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to read some random bytes to create the session secret. Error: %w", err)
		}
		randomBytesHash := sha256.Sum256(randomBytes)
		sessionSecret = hex.EncodeToString(randomBytesHash[:])
	}
	store := sessions.NewFilesystemStore(sessionsDir, []byte(sessionSecret))
	if store == nil {
		return fmt.Errorf("failed to get a session store")
	}
	SetStore(store)
	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteLaxMode // Strict mode causes issues when logging in via external identity provider.
	store.Options.Secure = common.Config.SecureCookies
	store.Options.MaxAge = common.Config.CookieMaxAge
	store.MaxLength(math.MaxInt16) // Required to prevent "securecookie: the value is too long" error. See https://github.com/markbates/goth/pull/141/files
	return nil
}

// GetSessionInfo returns info about the session.
func GetSessionInfo(r *http.Request) types.SessionInfo {
	logrus.Trace("GetSessionInfo start")
	defer logrus.Trace("GetSessionInfo end")
	session, _ := GetStore().Get(r, types.USER_SESSION_NAME)
	sessInfo := session.Values[types.SESSION_KEY_SESSION_INFO].(types.SessionInfo)
	return sessInfo
}

// SaveSessionInfo updates the info of an existing session.
func SaveSessionInfo(w http.ResponseWriter, r *http.Request, sessInfo types.SessionInfo) error {
	logrus.Trace("SaveSessionInfo start")
	defer logrus.Trace("SaveSessionInfo end")
	store := GetStore()
	session, _ := store.Get(r, types.USER_SESSION_NAME)
	session.Values[types.SESSION_KEY_SESSION_INFO] = sessInfo
	if err := store.Save(r, w, session); err != nil {
		return fmt.Errorf("failed to save the updated session. Error: %w", err)
	}
	return nil
}

// IsLoggedIn checks if the user has logged in already
func IsLoggedIn(r *http.Request) bool {
	logrus.Trace("IsLoggedIn start")
	defer logrus.Trace("IsLoggedIn end")
	sessInfo := GetSessionInfo(r)
	if sessInfo.Tokens.AccessToken == "" {
		logrus.Debug("the user access token is empty")
		return false
	}
	if _, err := crypto.DecodeAccessToken(sessInfo.Tokens.AccessToken); err != nil {
		logrus.Debugf("failed to get the decode the access token '%s' . Error: %q", string(sessInfo.Tokens.AccessToken), err)
		return false
	}
	return true
}

// ResetSession resets the given session
func ResetSession(session *sessions.Session) error {
	session.IsNew = true
	session.ID = ""
	session.Values[types.SESSION_KEY_SESSION_INFO] = types.SessionInfo{}
	return nil
}

// DeleteSession deletes the given session by setting max age to -1
func DeleteSession(w http.ResponseWriter, r *http.Request) error {
	session, _ := GetStore().Get(r, types.USER_SESSION_NAME)
	session.Options.MaxAge = -1
	if err := GetStore().Save(r, w, session); err != nil {
		return fmt.Errorf("failed to delete the session by saving with a negative max age. Error: %w", err)
	}
	return nil
}
