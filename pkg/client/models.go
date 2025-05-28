package client

import "github.com/google/uuid"

type UsersResponse struct {
	Users []User `json:"users"`
}

type GroupsResponse struct {
	Groups []Group `json:"groups"`
}

type RolesResponse struct {
	Roles []User `json:"roles"`
}

type User struct {
	ID            int      `json:"id,omitempty"`
	UUID          string   `json:"uuid,omitempty"`
	Username      string   `json:"username,omitempty"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	LastLogin     int64    `json:"lastlogin,omitempty"`
	Enabled       bool     `json:"enabled,omitempty"`
	Permissions   int      `json:"permissions,omitempty"`
	ContainerUUID string   `json:"container_uuid,omitempty"`
	RbacRoles     []Role   `json:"rbac_roles,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	GroupUUIDs    []string `json:"group_uuids,omitempty"`
}

type Role struct {
	UUID uuid.UUID `json:"uuid,omitempty"`
	Name string    `json:"name,omitempty"`
}

type UserRole struct {
	ContainerUUID string   `json:"container_uuid,omitempty"`
	UserUUID      string   `json:"user_uuid,omitempty"`
	RolesUUID     []string `json:"role_uuids,omitempty"`
}

type UserUpdateReqBody struct {
	Name        string `json:"name,omitempty"`
	Permissions int    `json:"permissions,omitempty"`
	Email       string `json:"email,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
}

type UserRoleReqBody struct {
	RolesUUIDs []string `json:"role_uuids,omitempty"`
}

type NewUser struct {
	Username string `json:"username,omitempty"`
	// The initial password for the user.
	// Passwords must be at least 12 characters long and contain:
	// at least one uppercase letter, one lowercase letter, one number,
	// and one special character symbol.
	Password    string `json:"password,omitempty"`
	Email       string `json:"email,omitempty"`
	Name        string `json:"name,omitempty"`
	Permissions int    `json:"permissions,omitempty"`
}

type Group struct {
	ID            int    `json:"id,omitempty"`
	UUID          string `json:"uuid,omitempty"`
	Name          string `json:"name,omitempty"`
	Permissions   int    `json:"permissions,omitempty"`
	UsersCount    int    `json:"users_count,omitempty"`
	ContainerUUID string `json:"container_uuid,omitempty"`
}

type PermissionsList struct {
	Permissions []Permission `json:"permissions,omitempty"`
}

type Permission struct {
	UUID      uuid.UUID       `json:"permission_uuid,omitempty"`
	Name      string          `json:"name,omitempty"`
	Actions   []string        `json:"actions,omitempty"`
	Objects   []TenableObject `json:"objects,omitempty"`
	Subjects  []TenableObject `json:"subjects,omitempty"`
	CreatedAt int64           `json:"created_at,omitempty"`
	CreatedBy string          `json:"created_by,omitempty"`
	UpdatedAt int64           `json:"updated_at,omitempty"`
	UpdatedBy string          `json:"updated_by,omitempty"`
}

type PermissionUpdateBody struct {
	Name     string          `json:"name,omitempty"`
	Actions  []string        `json:"actions,omitempty"`
	Objects  []TenableObject `json:"objects,omitempty"`
	Subjects []TenableObject `json:"subjects,omitempty"`
}

type TenableObject struct {
	Type string    `json:"type,omitempty"`
	UUID uuid.UUID `json:"uuid,omitempty"`
	Name string    `json:"name,omitempty"`
}
