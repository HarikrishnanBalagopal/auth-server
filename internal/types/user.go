package types

import (
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Role contains all the information about a RBAC role
type Role struct {
	Metadata `json:"metadata" mapstructure:"metadata"`
	Rules    []RoleRule `json:"rules" mapstructure:"rules"`
}

// RoleRule contains the list of resources and the verbs allowed on those resources
type RoleRule struct {
	Resources []string `json:"resources" mapstructure:"resources"`
	Verbs     []string `json:"verbs" mapstructure:"verbs"`
}

// Role is a role
type GoCloakRole struct {
	ID                 *string                   `json:"id,omitempty"`
	Name               *string                   `json:"name,omitempty"`
	ScopeParamRequired *bool                     `json:"scopeParamRequired,omitempty"`
	Composite          *bool                     `json:"composite,omitempty"`
	Composites         *CompositesRepresentation `json:"composites,omitempty"`
	ClientRole         *bool                     `json:"clientRole,omitempty"`
	ContainerID        *string                   `json:"containerId,omitempty"`
	Description        *string                   `json:"description,omitempty"`
	Attributes         *map[string][]string      `json:"attributes,omitempty"`
}

// CompositesRepresentation represents the composite roles of a role
type CompositesRepresentation struct {
	Client *map[string][]string `json:"client,omitempty"`
	Realm  *[]string            `json:"realm,omitempty"`
}

// User wraps the user info with other metadata.
type User struct {
	Id                string   `json:"id"`
	CreatedAt         string   `json:"created-at"`
	UpdatedAt         string   `json:"updated-at"`
	RoleIds           []string `json:"role-ids,omitempty"`
	IsServiceAccount  bool     `json:"is-service-account"`
	Password          []byte   `json:"password,omitempty"`
	NumFailedAttempts int      `json:"num-failed-attempts"`
	UserInfo
}

// UserInfo is returned by the userinfo endpoint
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type UserInfo struct {
	Sub                 *string          `json:"sub,omitempty"`
	Name                *string          `json:"name,omitempty"`
	GivenName           *string          `json:"given_name,omitempty"`
	FamilyName          *string          `json:"family_name,omitempty"`
	MiddleName          *string          `json:"middle_name,omitempty"`
	Nickname            *string          `json:"nickname,omitempty"`
	PreferredUsername   *string          `json:"preferred_username,omitempty"`
	Profile             *string          `json:"profile,omitempty"`
	Picture             *string          `json:"picture,omitempty"`
	Website             *string          `json:"website,omitempty"`
	Email               *string          `json:"email,omitempty"`
	EmailVerified       *bool            `json:"email_verified,omitempty"`
	Gender              *string          `json:"gender,omitempty"`
	ZoneInfo            *string          `json:"zoneinfo,omitempty"`
	Locale              *string          `json:"locale,omitempty"`
	PhoneNumber         *string          `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool            `json:"phone_number_verified,omitempty"`
	Address             *UserInfoAddress `json:"address,omitempty"`
	UpdatedAt           *int             `json:"updated_at,omitempty"`
}

// UserInfoAddress is representation of the address sub-filed of UserInfo
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type UserInfoAddress struct {
	Formatted     *string `json:"formatted,omitempty"`
	StreetAddress *string `json:"street_address,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postal_code,omitempty"`
	Country       *string `json:"country,omitempty"`
}

// RegisteredClient is a client that is allowed to use the services of this auth server.
type RegisteredClient struct {
	Id           string   `mapstructure:"id"`
	Secret       string   `mapstructure:"secret"`
	RedirectUrls []string `mapstructure:"redirect-urls"`
	RoleIds      []string `mapstructure:"role-ids"`
}

var (
	ErrServiceAccountWithPassword = fmt.Errorf("service accounts cannot have a password")
)

func NewUser(username, email string, isServiceAccount bool, password string) (User, error) {
	if username == "" || email == "" {
		return User{}, fmt.Errorf("the username and email cannot be empty")
	}
	userInfo := UserInfo{
		Sub:               &username,
		PreferredUsername: &username,
		Email:             &email,
	}
	user, err := NewUserFromUserInfo(userInfo, isServiceAccount)
	if err != nil {
		return user, err
	}
	if len(password) > 0 {
		if isServiceAccount {
			return user, ErrServiceAccountWithPassword
		}
		user.Password, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return user, fmt.Errorf("failed to hash the password for the user %+v . Error: %w", user, err)
		}
	}
	return user, nil
}

func NewUserFromUserInfo(userInfo UserInfo, isServiceAccount bool) (User, error) {
	if userInfo.Email == nil {
		return User{}, fmt.Errorf("the email cannot be empty")
	}
	id := *userInfo.Email
	return User{
		Id:               id,
		UserInfo:         userInfo,
		IsServiceAccount: isServiceAccount,
	}, nil
}

// GetRulesAsAttrs flattens and returns the rules of the role as a map suitable for creating an authz server role
func (r Role) GetRulesAsAttrs() map[string][]string {
	attrs := map[string][]string{}
	for _, rule := range r.Rules {
		for _, res := range rule.Resources {
			attrs[res] = append(attrs[res], rule.Verbs...)
		}
	}
	return attrs
}

// ToAuthServerRole converts the role to an authz server role
func (r Role) ToAuthServerRole() (GoCloakRole, error) {
	// since keycloak doesn't allow us to choose the role id,
	// we are storing the role id they give us in the name field of keycloak role (the role name field is unique in keycloak)
	// and we store both name and description they give us in the description field of keycloak role as json
	roleNameDescBytes, err := json.Marshal(map[string]string{"name": r.Name, "description": r.Description, "timestamp": r.Timestamp})
	if err != nil {
		return GoCloakRole{}, fmt.Errorf("failed to marshal the role to an auth server role. Error: %q", err)
	}
	roleNameDesc := string(roleNameDescBytes)
	attrs := r.GetRulesAsAttrs()
	return GoCloakRole{ID: &r.Id, Name: &r.Id, Description: &roleNameDesc, Attributes: &attrs}, nil
}

// FromAuthServerRole converts an authz server role to a role
func FromAuthServerRole(r GoCloakRole) Role {
	// since keycloak doesn't allow us to choose the role id,
	// we are storing the role id they give us in the name field of keycloak role (the role name field is unique in keycloak)
	// and we store both name and description they give us in the description field of keycloak role as json
	name := ""
	description := ""
	timestamp := ""
	if r.Description != nil {
		roleMap := map[string]string{}
		if err := json.Unmarshal([]byte(*r.Description), &roleMap); err == nil {
			name = roleMap["name"]
			description = roleMap["description"]
			timestamp = roleMap["timestamp"]
		}
	}
	rules := []RoleRule{}
	if r.Attributes != nil {
		for res, verbs := range *r.Attributes {
			rules = append(rules, RoleRule{Resources: []string{res}, Verbs: verbs})
		}
	}
	return Role{Metadata: Metadata{Id: *r.Name, Name: name, Description: description, Timestamp: timestamp}, Rules: rules}
}
