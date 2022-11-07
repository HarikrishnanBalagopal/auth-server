package types

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// SessionInfo contains data for a user session
type SessionInfo struct {
	Id            string `json:"id"`
	Tokens        Tokens `json:"tokens"`
	User          User   `json:"user"`
	RedirectUrl   string `json:"redirect_uri"`
	PreviousState string `json:"previous_state"`
	CsrfToken     string `json:"csrf_token"`
}

// GetCSRFToken returns a random string to use as the CSRF token based on the session
func (sessInfo *SessionInfo) GetCSRFToken() string {
	csrfBytes := sha256.Sum256([]byte(sessInfo.Id))
	return hex.EncodeToString(csrfBytes[:])
}

// IsValidCSRFToken checks the provided access token against the CSRF token generated from the session
func (sessInfo *SessionInfo) IsValidCSRFToken(actualCSRFToken string) bool {
	return subtle.ConstantTimeCompare([]byte(sessInfo.GetCSRFToken()), []byte(actualCSRFToken)) == 1
}
