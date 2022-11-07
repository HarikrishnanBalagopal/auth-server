package database

import (
	"errors"
	"fmt"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
)

// IDatabase defines an interface that can manage Move2Kube workspaces and projects
type IDatabase interface {
	GetSupportInfo() map[string]string

	SetAuthCodeToLoginData(code string, data types.LoginData) error
	GetLoginDataFromAuthCode(code string) (types.LoginData, error)

	ListUsers(ids []string) ([]types.User, error)
	CreateUser(user types.User) error
	ReadUser(id string) (types.User, error)
	UpdateUser(user types.User) error
	DeleteUser(id string) error

	ListRoles(ids []string) ([]types.Role, error)
	CreateRole(role types.Role) error
	ReadRole(id string) (types.Role, error)
	UpdateRole(role types.Role) error
	DeleteRole(id string) error

	AddOrRemoveRoles(userId string, roleIds []string, add bool) error
}

func NewDatabase() (IDatabase, error) {
	logrus.Trace("NewDatabase start")
	defer logrus.Trace("NewDatabase end")
	fs, err := NewFileBasedDatabase()
	if err != nil {
		return fs, fmt.Errorf("failed to create a new file based database. Error: %w", err)
	}
	initialRoles := []types.Role{
		common.AdminRole,
		common.CreateGetUserInfoRole(),
		common.CreateCreateRPTRole(),
	}
	logrus.Debug("add a role for each role in the config")
	initialRoles = append(initialRoles, common.Config.Roles...)
	for _, initialRole := range initialRoles {
		logrus.Debugf("checking if the role exists: %+v", initialRole)
		if _, err := fs.ReadRole(initialRole.Id); err != nil {
			if !errors.Is(err, types.ErrNotFound) {
				return fs, fmt.Errorf("failed to read the role with id '%s' in the database. Error: %w", initialRole.Id, err)
			}
			logrus.Debug("the role does not exist, creating the role")
			if err := fs.CreateRole(initialRole); err != nil {
				return fs, fmt.Errorf("failed to create the role %+v in the database. Error: %w", initialRole, err)
			}
		}
	}
	{
		logrus.Debug("add a user for each registered client")
		for _, client := range common.Config.RegisteredClients {
			for _, roleId := range client.RoleIds {
				if _, err := fs.ReadRole(roleId); err != nil {
					return fs, fmt.Errorf("failed to read the role with id '%s' in the database. Error: %w", roleId, err)
				}
			}
			user, err := types.NewUser(client.Id, client.Id, true, "")
			if err != nil {
				return fs, fmt.Errorf("failed to create a service account for the client %+v in the database. Error: %w", client, err)
			}
			user.RoleIds = client.RoleIds
			logrus.Debugf("checking if the user exists: %+v", user)
			if _, err := fs.ReadUser(user.Id); err != nil {
				if !errors.Is(err, types.ErrNotFound) {
					return fs, fmt.Errorf("failed to read the user with id '%s' in the database. Error: %w", user.Id, err)
				}
				logrus.Debug("the user does not exist, creating the user")
				if err := fs.CreateUser(user); err != nil {
					return fs, fmt.Errorf("failed to create the user %+v in the database. Error: %w", user, err)
				}
			}
		}
	}
	{
		logrus.Debug("add a user for each user in the config")
		for _, configUser := range common.Config.Users {
			for _, roleId := range configUser.RoleIds {
				if _, err := fs.ReadRole(roleId); err != nil {
					return fs, fmt.Errorf("failed to read the role with id '%s' in the database. Error: %w", roleId, err)
				}
			}
			user, err := types.NewUser(configUser.Id, configUser.Email, configUser.IsServiceAccount, configUser.Password)
			if err != nil {
				return fs, fmt.Errorf("failed to create a user object for the user %+v in the config. Error: %w", configUser, err)
			}
			user.RoleIds = configUser.RoleIds
			logrus.Debugf("checking if the user exists: %+v", user)
			if _, err := fs.ReadUser(user.Id); err != nil {
				if !errors.Is(err, types.ErrNotFound) {
					return fs, fmt.Errorf("failed to read the user with id '%s' in the database. Error: %w", user.Id, err)
				}
				logrus.Debug("the user does not exist, creating the user")
				if err := fs.CreateUser(user); err != nil {
					return fs, fmt.Errorf("failed to create the user %+v in the database. Error: %w", user, err)
				}
			}
		}
	}
	return fs, nil
}
