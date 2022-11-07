package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/konveyor/auth-server/internal/common"
	"github.com/konveyor/auth-server/internal/common/version"
	"github.com/konveyor/auth-server/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	bolt "go.etcd.io/bbolt"
)

type FileBasedDatabase struct{}

const (
	// DEFAULT_DIRECTORY_PERMISSIONS is the default permissions used when creating new directories
	DEFAULT_DIRECTORY_PERMISSIONS os.FileMode = 0770
	// DEFAULT_FILE_PERMISSIONS is the default permissions used when creating new files
	DEFAULT_FILE_PERMISSIONS os.FileMode = 0660
	// DATABASE_FILENAME is the database filename
	DATABASE_FILENAME = "auth-server-database"
	// USERS_BUCKET is the name of the bucket containing all the users
	USERS_BUCKET = "users"
	// ROLES_BUCKET is the name of the bucket containing all the roles
	ROLES_BUCKET = "roles"
	// LOGIN_BUCKET is the name of the bucket containing login data
	LOGIN_BUCKET = "login"
)

var (
	// ErrBucketIsMissing is the error returned when the required bucket is missing from the database.
	ErrBucketIsMissing = fmt.Errorf("bucket is missing")
)

func NewFileBasedDatabase() (IDatabase, error) {
	logrus.Trace("NewFileSystem start")
	defer logrus.Trace("NewFileSystem end")
	fs := new(FileBasedDatabase)
	if common.Config.CleanStartup {
		logrus.Infof("deleting the data directory if it already exists at path '%s'", common.Config.DataDir)
		if err := os.RemoveAll(common.Config.DataDir); err != nil {
			return fs, fmt.Errorf("failed to remove the data directory at path '%s' . Error: %w", common.Config.DataDir, err)
		}
	}
	logrus.Infof("creating the data directory at path '%s'", common.Config.DataDir)
	if err := os.MkdirAll(common.Config.DataDir, DEFAULT_DIRECTORY_PERMISSIONS); err != nil {
		return fs, fmt.Errorf("failed to make the data directory at path '%s' . Error: %w", common.Config.DataDir, err)
	}
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fs, fmt.Errorf("failed to create/get the database in read/write mode while setting up handlers. Error: %w", err)
	}
	err = db.Update(func(t *bolt.Tx) error {
		if _, err := t.CreateBucketIfNotExists([]byte(LOGIN_BUCKET)); err != nil {
			return err
		}
		if _, err := t.CreateBucketIfNotExists([]byte(USERS_BUCKET)); err != nil {
			return err
		}
		if _, err := t.CreateBucketIfNotExists([]byte(ROLES_BUCKET)); err != nil {
			return err
		}
		return nil
	})
	db.Close()
	if err != nil {
		return fs, fmt.Errorf("failed to create the buckets in the database. Error: %w", err)
	}
	return fs, nil
}

// GetDatabase returns the database. The database must be closed by the caller.
func (*FileBasedDatabase) GetDatabase(readOnly bool) (*bolt.DB, error) {
	logrus.Trace("FileSystem.GetDatabase start")
	defer logrus.Trace("FileSystem.GetDatabase end")
	databasePath := filepath.Join(common.Config.DataDir, DATABASE_FILENAME)
	db, err := bolt.Open(databasePath, DEFAULT_FILE_PERMISSIONS, &bolt.Options{ReadOnly: readOnly})
	if err != nil {
		return db, fmt.Errorf("failed to open the database at the path '%s' . Error: %w", databasePath, err)
	}
	return db, nil
}

func (*FileBasedDatabase) GetSupportInfo() map[string]string {
	logrus.Trace("FileSystem.GetSupportInfo start")
	defer logrus.Trace("FileSystem.GetSupportInfo end")
	return map[string]string{"version": version.GetVersion(true)}
}

// GetLoginDataFromAuthCode gets the login info for the given auth code.
func (fs *FileBasedDatabase) GetLoginDataFromAuthCode(code string) (types.LoginData, error) {
	logrus.Trace("FileSystem.GetLoginDataFromAuthCode start")
	defer logrus.Trace("FileSystem.GetLoginDataFromAuthCode end")
	db, err := fs.GetDatabase(true)
	if err != nil {
		return types.LoginData{}, fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	data := types.LoginData{}
	err = db.View(func(t *bolt.Tx) error {
		data, err = fs.getLoginDataFromAuthCode(t, code)
		return err
	})
	return data, err
}

func (fs *FileBasedDatabase) getLoginDataFromAuthCode(t *bolt.Tx, code string) (types.LoginData, error) {
	loginBucket := t.Bucket([]byte(LOGIN_BUCKET))
	if loginBucket == nil {
		return types.LoginData{}, ErrBucketIsMissing
	}
	dataBytes := loginBucket.Get([]byte(code))
	if dataBytes == nil {
		return types.LoginData{}, types.ErrNotFound
	}
	data := types.LoginData{}
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return data, fmt.Errorf("failed to unmarshal the json as login data. Error: %w", err)
	}
	return data, nil
}

// SetAuthCodeToLoginData sets auth code to certain login info.
func (fs *FileBasedDatabase) SetAuthCodeToLoginData(code string, data types.LoginData) error {
	logrus.Trace("FileSystem.SetAuthCodeToLoginData start")
	defer logrus.Trace("FileSystem.SetAuthCodeToLoginData end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.setAuthCodeToLoginData(t, code, data)
	})
}

func (fs *FileBasedDatabase) setAuthCodeToLoginData(t *bolt.Tx, code string, data types.LoginData) error {
	loginBucket := t.Bucket([]byte(LOGIN_BUCKET))
	if loginBucket == nil {
		return ErrBucketIsMissing
	}
	if loginBucket.Get([]byte(code)) != nil {
		return types.ErrAlreadyExist
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal the login data as json. Error: %w", err)
	}
	if err := loginBucket.Put([]byte(code), dataBytes); err != nil {
		return fmt.Errorf("failed to set the auth code '%s' to the login data '%s' in the login bucket. Error: %w", code, string(dataBytes), err)
	}
	return nil
}

// ListUsers lists all the existing users with the given ids.
// If ids is nil then it returns all the users.
func (fs *FileBasedDatabase) ListUsers(ids []string) ([]types.User, error) {
	logrus.Trace("FileSystem.ListUsers start")
	defer logrus.Trace("FileSystem.ListUsers end")
	db, err := fs.GetDatabase(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	users := []types.User{}
	err = db.View(func(t *bolt.Tx) error {
		users, err = fs.listUsers(t, ids)
		return err
	})
	return users, err
}

func (*FileBasedDatabase) listUsers(t *bolt.Tx, ids []string) ([]types.User, error) {
	users := []types.User{}
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return users, ErrBucketIsMissing
	}
	err := usersBucket.ForEach(func(id, userBytes []byte) error {
		if ids != nil && common.Find(ids, string(id)) == -1 {
			return nil
		}
		user := types.User{}
		if err := json.Unmarshal(userBytes, &user); err != nil {
			logrus.Errorf("failed to unmarshal the user with id '%s' as json. Actual: '%s' Error: %w", string(id), string(userBytes), err)
			return nil
		}
		users = append(users, user)
		return nil
	})
	return users, err
}

// CreateUser creates a new user.
func (fs *FileBasedDatabase) CreateUser(user types.User) error {
	logrus.Trace("FileSystem.CreateUser start")
	defer logrus.Trace("FileSystem.CreateUser end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	user.CreatedAt = cast.ToString(time.Now().Unix())
	user.UpdatedAt = user.CreatedAt
	return db.Update(func(t *bolt.Tx) error {
		return fs.createUser(t, user)
	})
}

func (*FileBasedDatabase) createUser(t *bolt.Tx, user types.User) error {
	if err := validateUser(user); err != nil {
		return fmt.Errorf("invalid user. Error: %w", err)
	}
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return ErrBucketIsMissing
	}
	if usersBucket.Get([]byte(user.Id)) != nil {
		return types.ErrAlreadyExist
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal the user as json. Error: %w", err)
	}
	if err := usersBucket.Put([]byte(user.Id), userBytes); err != nil {
		return fmt.Errorf("failed to set the id '%s' to the user '%s' in the users bucket. Error: %w", user.Id, string(userBytes), err)
	}
	return nil
}

func validateUser(user types.User) error {
	if user.Id == "" {
		return fmt.Errorf("the id is empty")
	}
	if user.Email == nil {
		return fmt.Errorf("the email is empty")
	}
	if user.Id != *user.Email {
		return fmt.Errorf("the id and email are different")
	}
	return nil
}

// ReadUser gets an existing user.
func (fs *FileBasedDatabase) ReadUser(id string) (types.User, error) {
	logrus.Trace("FileSystem.ReadUser start")
	defer logrus.Trace("FileSystem.ReadUser end")
	db, err := fs.GetDatabase(true)
	if err != nil {
		return types.User{}, fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	user := types.User{}
	err = db.View(func(t *bolt.Tx) error {
		user, err = fs.readUser(t, id)
		return err
	})
	return user, err
}

func (*FileBasedDatabase) readUser(t *bolt.Tx, id string) (types.User, error) {
	user := types.User{}
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return user, ErrBucketIsMissing
	}
	userBytes := usersBucket.Get([]byte(id))
	if userBytes == nil {
		return user, types.ErrNotFound
	}
	if err := json.Unmarshal(userBytes, &user); err != nil {
		return user, fmt.Errorf("failed to unmarshal the workspace as json. Actual: '%s' Error: %w", string(userBytes), err)
	}
	return user, nil
}

// UpdateUser updates an existing user.
func (fs *FileBasedDatabase) UpdateUser(user types.User) error {
	logrus.Trace("FileSystem.UpdateUser start")
	defer logrus.Trace("FileSystem.UpdateUser end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.updateUser(t, user)
	})
}

func (*FileBasedDatabase) updateUser(t *bolt.Tx, user types.User) error {
	if err := validateUser(user); err != nil {
		return fmt.Errorf("invalid user. Error: %w", err)
	}
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return ErrBucketIsMissing
	}
	if usersBucket.Get([]byte(user.Id)) == nil {
		return types.ErrNotFound
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal the user as json. Error: %w", err)
	}
	if err := usersBucket.Put([]byte(user.Id), userBytes); err != nil {
		return fmt.Errorf("failed to set the id '%s' to the user '%s' in the users bucket. Error: %w", user.Id, string(userBytes), err)
	}
	return nil
}

// DeleteUser deletes an existing user.
func (fs *FileBasedDatabase) DeleteUser(id string) error {
	logrus.Trace("FileSystem.DeleteUser start")
	defer logrus.Trace("FileSystem.DeleteUser end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.deleteUser(t, id)
	})
}

func (fs *FileBasedDatabase) deleteUser(t *bolt.Tx, id string) error {
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return ErrBucketIsMissing
	}
	if usersBucket.Get([]byte(id)) == nil {
		return types.ErrNotFound
	}
	if err := usersBucket.Delete([]byte(id)); err != nil {
		return fmt.Errorf("failed to delete the id '%s' in the users bucket. Error: %w", id, err)
	}
	return nil
}

// ListRoles lists all the existing roles with the given ids.
// If ids is nil then it returns all the roles.
func (fs *FileBasedDatabase) ListRoles(ids []string) ([]types.Role, error) {
	logrus.Trace("FileSystem.ListRoles start")
	defer logrus.Trace("FileSystem.ListRoles end")
	db, err := fs.GetDatabase(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	roles := []types.Role{}
	err = db.View(func(t *bolt.Tx) error {
		roles, err = fs.listRoles(t, ids)
		return err
	})
	return roles, err
}

func (*FileBasedDatabase) listRoles(t *bolt.Tx, ids []string) ([]types.Role, error) {
	roles := []types.Role{}
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return roles, ErrBucketIsMissing
	}
	err := rolesBucket.ForEach(func(id, roleBytes []byte) error {
		if ids != nil && common.Find(ids, string(id)) == -1 {
			return nil
		}
		role := types.Role{}
		if err := json.Unmarshal(roleBytes, &role); err != nil {
			logrus.Errorf("failed to unmarshal the role with id '%s' as json. Actual: '%s' Error: %w", string(id), string(roleBytes), err)
			return nil
		}
		roles = append(roles, role)
		return nil
	})
	return roles, err
}

// CreateRole creates a new role.
func (fs *FileBasedDatabase) CreateRole(role types.Role) error {
	logrus.Tracef("FileSystem.CreateRole start: %+v", role)
	defer logrus.Trace("FileSystem.CreateRole end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	role.Timestamp = cast.ToString(time.Now().Unix())
	return db.Update(func(t *bolt.Tx) error {
		return fs.createRole(t, role)
	})
}

func (*FileBasedDatabase) createRole(t *bolt.Tx, role types.Role) error {
	if err := validateRole(role); err != nil {
		return fmt.Errorf("invalid role. Error: %w", err)
	}
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return ErrBucketIsMissing
	}
	if rolesBucket.Get([]byte(role.Id)) != nil {
		return types.ErrAlreadyExist
	}
	roleBytes, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal the role as json. Error: %w", err)
	}
	if err := rolesBucket.Put([]byte(role.Id), roleBytes); err != nil {
		return fmt.Errorf("failed to set the id '%s' to the role '%s' in the users bucket. Error: %w", role.Id, string(roleBytes), err)
	}
	return nil
}

func validateRole(role types.Role) error {
	if role.Id == "" {
		return fmt.Errorf("the id is empty")
	}
	return nil
}

// ReadRole gets an existing role.
func (fs *FileBasedDatabase) ReadRole(id string) (types.Role, error) {
	logrus.Trace("FileSystem.ReadRole start")
	defer logrus.Trace("FileSystem.ReadRole end")
	db, err := fs.GetDatabase(true)
	if err != nil {
		return types.Role{}, fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	role := types.Role{}
	err = db.View(func(t *bolt.Tx) error {
		role, err = fs.readRole(t, id)
		return err
	})
	return role, err
}

func (*FileBasedDatabase) readRole(t *bolt.Tx, id string) (types.Role, error) {
	role := types.Role{}
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return role, ErrBucketIsMissing
	}
	roleBytes := rolesBucket.Get([]byte(id))
	if roleBytes == nil {
		return role, types.ErrNotFound
	}
	if err := json.Unmarshal(roleBytes, &role); err != nil {
		return role, fmt.Errorf("failed to unmarshal the workspace as json. Actual: '%s' Error: %w", string(roleBytes), err)
	}
	return role, nil
}

// UpdateRole updates an existing role.
func (fs *FileBasedDatabase) UpdateRole(role types.Role) error {
	logrus.Trace("FileSystem.UpdateRole start")
	defer logrus.Trace("FileSystem.UpdateRole end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.updateRole(t, role)
	})
}

func (*FileBasedDatabase) updateRole(t *bolt.Tx, role types.Role) error {
	if err := validateRole(role); err != nil {
		return fmt.Errorf("invalid role. Error: %w", err)
	}
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return ErrBucketIsMissing
	}
	if rolesBucket.Get([]byte(role.Id)) == nil {
		return types.ErrNotFound
	}
	roleBytes, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("failed to marshal the role as json. Error: %w", err)
	}
	if err := rolesBucket.Put([]byte(role.Id), roleBytes); err != nil {
		return fmt.Errorf("failed to set the id '%s' to the role '%s' in the roles bucket. Error: %w", role.Id, string(roleBytes), err)
	}
	return nil
}

// DeleteRole deletes an existing role.
func (fs *FileBasedDatabase) DeleteRole(id string) error {
	logrus.Trace("FileSystem.DeleteRole start")
	defer logrus.Trace("FileSystem.DeleteRole end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.deleteRole(t, id)
	})
}

func (fs *FileBasedDatabase) deleteRole(t *bolt.Tx, id string) error {
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return ErrBucketIsMissing
	}
	if rolesBucket.Get([]byte(id)) == nil {
		return types.ErrNotFound
	}
	if err := rolesBucket.Delete([]byte(id)); err != nil {
		return fmt.Errorf("failed to delete the id '%s' in the roles bucket. Error: %w", id, err)
	}
	users, err := fs.listUsers(t, nil)
	if err != nil {
		return err
	}
	for _, user := range users {
		user.RoleIds = common.Filter(func(x string) bool { return x != id }, user.RoleIds)
		if err := fs.updateUser(t, user); err != nil {
			return err
		}
	}
	return nil
}

// AddOrRemoveRoles adds/removes roles with the given ids to/from the user.
func (fs *FileBasedDatabase) AddOrRemoveRoles(userId string, roleIds []string, add bool) error {
	logrus.Trace("FileSystem.AddOrRemoveRoles start")
	defer logrus.Trace("FileSystem.AddOrRemoveRoles end")
	db, err := fs.GetDatabase(false)
	if err != nil {
		return fmt.Errorf("failed to get the database. Error: %w", err)
	}
	defer db.Close()
	return db.Update(func(t *bolt.Tx) error {
		return fs.addRolesToUser(t, userId, roleIds, add)
	})
}

func (fs *FileBasedDatabase) addRolesToUser(t *bolt.Tx, userId string, roleIds []string, add bool) error {
	usersBucket := t.Bucket([]byte(USERS_BUCKET))
	if usersBucket == nil {
		return ErrBucketIsMissing
	}
	rolesBucket := t.Bucket([]byte(ROLES_BUCKET))
	if rolesBucket == nil {
		return ErrBucketIsMissing
	}
	user, err := fs.readUser(t, userId)
	if err != nil {
		return fmt.Errorf("failed to get the user. Error: %w", err)
	}
	if add {
		for _, roleId := range roleIds {
			if _, err := fs.readRole(t, roleId); err != nil {
				return fmt.Errorf("failed to get the role. Error: %w", err)
			}
			if common.Find(user.RoleIds, roleId) == -1 {
				user.RoleIds = append(user.RoleIds, roleId)
			}
		}
	} else {
		updatedRoles := []string{}
		for _, roleId := range user.RoleIds {
			if common.Find(roleIds, roleId) == -1 {
				updatedRoles = append(updatedRoles, roleId)
			}
		}
		user.RoleIds = updatedRoles
	}
	if err := fs.updateUser(t, user); err != nil {
		return fmt.Errorf("failed to update the user's roles. Error: %w", err)
	}
	return nil
}
