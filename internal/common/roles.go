package common

import "github.com/konveyor/auth-server/internal/types"

var (
	// AdminRole is the administrator role that has permission to access to all resources with all verbs.
	AdminRole = types.Role{
		Metadata: types.Metadata{Id: "admin"},
		Rules: []types.RoleRule{{
			Resources: []string{".*"},
			Verbs:     []string{types.VERB_ALL_PERMS},
		}},
	}
)

// CreateGetUserInfoRole is the role that has permission to access the user info of a user.
func CreateGetUserInfoRole() types.Role {
	return types.Role{
		Metadata: types.Metadata{Id: "get-user-info"},
		Rules: []types.RoleRule{{
			Resources: []string{"^" + GetUserInfoEndpointPath() + "$"},
			Verbs:     []string{"GET"},
		}},
	}
}

// CreateCreateRPTRole is the role that has permission to create a RPT for the user.
func CreateCreateRPTRole() types.Role {
	return types.Role{
		Metadata: types.Metadata{Id: "create-rpt"},
		Rules: []types.RoleRule{{
			Resources: []string{"^" + GetRPTEndpointPath() + "$"},
			Verbs:     []string{"POST"},
		}},
	}
}

// AddDefaultRolesToUser adds the getUserInfo and create RPT role to all users
func AddDefaultRolesToUser(user types.User) types.User {
	user.RoleIds = AppendIfNotPresent(
		user.RoleIds,
		CreateGetUserInfoRole().Id,
		CreateCreateRPTRole().Id,
	)
	return user
}
