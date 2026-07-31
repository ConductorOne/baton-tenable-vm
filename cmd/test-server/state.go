package main

import (
	"slices"
	"sync"
)

// User mirrors the Tenable user object returned by GET /users.
// Doc URL: https://developer.tenable.com/reference/users-list
// enabled is intentionally NOT omitempty so disabled users serialize as false.
type User struct {
	UUID          string     `json:"uuid"`
	ID            int        `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	Permissions   int        `json:"permissions"`
	Enabled       bool       `json:"enabled"`
	ContainerUUID string     `json:"container_uuid"`
	GroupUUIDs    []string   `json:"group_uuids,omitempty"`
	RbacRoles     []RbacRole `json:"rbac_roles,omitempty"`
}

// RbacRole is the nested role object included when withRoles=true.
type RbacRole struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// Group mirrors the Tenable group object returned by GET /groups.
// Doc URL: https://developer.tenable.com/reference/groups-list
// Field name is user_count (singular) per the OpenAPI schema — not users_count.
type Group struct {
	UUID          string `json:"uuid"`
	ID            int    `json:"id"`
	Name          string `json:"name"`
	UserCount     int    `json:"user_count"`
	ContainerUUID string `json:"container_uuid"`
}

// Role mirrors the Tenable role object returned by GET /access-control/v1/roles.
// Doc URL: https://developer.tenable.com/reference/access-control-roles-list
// Response is a raw JSON array (not wrapped).
type Role struct {
	UUID                  string   `json:"uuid"`
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	RolePermissionStrings []string `json:"role_permission_strings"`
	Type                  string   `json:"type"`
	Status                string   `json:"status"`
}

// PermissionSubject is a user or group the permission is granted to.
// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permissions-list
type PermissionSubject struct {
	Type string `json:"type"`
	UUID string `json:"uuid,omitempty"`
	Name string `json:"name,omitempty"`
}

// PermissionObject is the tag/asset scope of a permission.
type PermissionObject struct {
	Type string `json:"type"`
	UUID string `json:"uuid,omitempty"`
	Name string `json:"name,omitempty"`
}

// Permission mirrors GET /api/v3/access-control/permissions.
type Permission struct {
	UUID      string              `json:"permission_uuid"`
	Name      string              `json:"name"`
	Actions   []string            `json:"actions"`
	Objects   []PermissionObject  `json:"objects"`
	Subjects  []PermissionSubject `json:"subjects"`
	CreatedAt int64               `json:"created_at,omitempty"`
	CreatedBy string              `json:"created_by,omitempty"`
	UpdatedAt int64               `json:"updated_at,omitempty"`
	UpdatedBy string              `json:"updated_by,omitempty"`
}

// State is the in-memory Tenable container. Every access goes through a
// locking method — handlers never touch the maps directly.
type State struct {
	mu sync.Mutex

	containerUUID string
	nextUserID    int
	nextGroupID   int

	users       map[string]*User // uuid → user
	usersByID   map[int]*User
	userList    []*User
	groups      map[string]*Group // uuid → group
	groupsByID  map[int]*Group
	groupList   []*Group
	roles       map[string]*Role
	roleList    []*Role
	permissions map[string]*Permission
	permList    []*Permission

	// Edge tables keyed by ID strings (not pointers).
	groupMembers map[string][]string // groupUUID → []userUUID
	userRoles    map[string][]string // userUUID → []roleUUID
}

func NewState() *State {
	s := &State{
		containerUUID: containerUUID,
		nextUserID:    1000,
		nextGroupID:   100,
		users:         make(map[string]*User),
		usersByID:     make(map[int]*User),
		groups:        make(map[string]*Group),
		groupsByID:    make(map[int]*Group),
		roles:         make(map[string]*Role),
		permissions:   make(map[string]*Permission),
		groupMembers:  make(map[string][]string),
		userRoles:     make(map[string][]string),
	}
	seed(s)
	return s
}

func (s *State) ListUsers() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.userList))
	for _, u := range s.userList {
		out = append(out, s.copyUserLocked(u))
	}
	return out
}

func (s *State) GetUserByUUID(uuid string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[uuid]
	if !ok {
		return User{}, false
	}
	return s.copyUserLocked(u), true
}

func (s *State) GetUserByID(id int) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return User{}, false
	}
	return s.copyUserLocked(u), true
}

func (s *State) CreateUser(username, email, name string, permissions int) User {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextUserID++
	id := s.nextUserID
	uuid := newDeterministicUUID("user", id)
	u := &User{
		UUID:          uuid,
		ID:            id,
		Username:      username,
		Email:         email,
		Name:          name,
		Permissions:   permissions,
		Enabled:       true,
		ContainerUUID: s.containerUUID,
		GroupUUIDs:    []string{allUsersGroupUUID},
	}
	s.users[uuid] = u
	s.usersByID[id] = u
	s.userList = append(s.userList, u)
	s.groupMembers[allUsersGroupUUID] = append(s.groupMembers[allUsersGroupUUID], uuid)
	s.recomputeGroupCountsLocked()
	return s.copyUserLocked(u)
}

func (s *State) DeleteUser(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return false
	}
	delete(s.users, u.UUID)
	delete(s.usersByID, id)
	delete(s.userRoles, u.UUID)
	s.userList = slices.DeleteFunc(s.userList, func(x *User) bool { return x.UUID == u.UUID })
	for gUUID, members := range s.groupMembers {
		s.groupMembers[gUUID] = slices.DeleteFunc(members, func(m string) bool { return m == u.UUID })
	}
	s.recomputeGroupCountsLocked()
	return true
}

func (s *State) SetUserEnabled(id int, enabled bool) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return User{}, false
	}
	u.Enabled = enabled
	return s.copyUserLocked(u), true
}

func (s *State) UpdateUser(id int, name string, permissions int, email string, enabled bool) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return User{}, false
	}
	if name != "" {
		u.Name = name
	}
	if email != "" {
		u.Email = email
	}
	if permissions != 0 {
		u.Permissions = permissions
	}
	u.Enabled = enabled
	return s.copyUserLocked(u), true
}

func (s *State) ListGroups() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Group, 0, len(s.groupList))
	for _, g := range s.groupList {
		cp := *g
		out = append(out, cp)
	}
	return out
}

func (s *State) GetGroupByID(id int) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groupsByID[id]
	if !ok {
		return Group{}, false
	}
	return *g, true
}

func (s *State) ListGroupMembers(groupID int) ([]User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groupsByID[groupID]
	if !ok {
		return nil, false
	}
	members := s.groupMembers[g.UUID]
	out := make([]User, 0, len(members))
	for _, uUUID := range members {
		if u, ok := s.users[uUUID]; ok {
			out = append(out, s.copyUserLocked(u))
		}
	}
	return out, true
}

// AddGroupMember returns (alreadyMember, ok). ok=false means group or user missing.
func (s *State) AddGroupMember(groupID, userID int) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groupsByID[groupID]
	if !ok {
		return false, false
	}
	u, ok := s.usersByID[userID]
	if !ok {
		return false, false
	}
	if slices.Contains(s.groupMembers[g.UUID], u.UUID) {
		return true, true
	}
	s.groupMembers[g.UUID] = append(s.groupMembers[g.UUID], u.UUID)
	if !slices.Contains(u.GroupUUIDs, g.UUID) {
		u.GroupUUIDs = append(u.GroupUUIDs, g.UUID)
	}
	s.recomputeGroupCountsLocked()
	return false, true
}

// RemoveGroupMember returns (alreadyRemoved, ok).
func (s *State) RemoveGroupMember(groupID, userID int) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groupsByID[groupID]
	if !ok {
		return false, false
	}
	u, ok := s.usersByID[userID]
	if !ok {
		return false, false
	}
	if !slices.Contains(s.groupMembers[g.UUID], u.UUID) {
		return true, true
	}
	s.groupMembers[g.UUID] = slices.DeleteFunc(s.groupMembers[g.UUID], func(m string) bool { return m == u.UUID })
	u.GroupUUIDs = slices.DeleteFunc(u.GroupUUIDs, func(m string) bool { return m == g.UUID })
	s.recomputeGroupCountsLocked()
	return false, true
}

func (s *State) ListRoles() []Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Role, 0, len(s.roleList))
	for _, r := range s.roleList {
		out = append(out, *r)
	}
	return out
}

func (s *State) GetUserRoles(userUUID string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userUUID]; !ok {
		return nil, false
	}
	return slices.Clone(s.userRoles[userUUID]), true
}

// SetUserRoles replaces the user's role list (Tenable assigns one role at a time
// in practice; the API body is still an array of role_uuids).
func (s *State) SetUserRoles(userUUID string, roleUUIDs []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userUUID]
	if !ok {
		return false
	}
	for _, roleUUID := range roleUUIDs {
		if _, ok := s.roles[roleUUID]; !ok {
			return false
		}
	}
	s.userRoles[userUUID] = slices.Clone(roleUUIDs)
	u.RbacRoles = nil
	for _, roleUUID := range roleUUIDs {
		r := s.roles[roleUUID]
		u.RbacRoles = append(u.RbacRoles, RbacRole{UUID: r.UUID, Name: r.Name})
	}
	return true
}

func (s *State) ListPermissions() []Permission {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Permission, 0, len(s.permList))
	for _, p := range s.permList {
		out = append(out, copyPermission(p))
	}
	return out
}

func (s *State) GetPermission(uuid string) (Permission, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.permissions[uuid]
	if !ok {
		return Permission{}, false
	}
	return copyPermission(p), true
}

func (s *State) UpdatePermission(uuid string, name string, actions []string, objects []PermissionObject, subjects []PermissionSubject) (Permission, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.permissions[uuid]
	if !ok {
		return Permission{}, false
	}
	p.Name = name
	p.Actions = slices.Clone(actions)
	p.Objects = slices.Clone(objects)
	p.Subjects = slices.Clone(subjects)
	return copyPermission(p), true
}

func (s *State) copyUserLocked(u *User) User {
	cp := *u
	cp.GroupUUIDs = slices.Clone(u.GroupUUIDs)
	cp.RbacRoles = slices.Clone(u.RbacRoles)
	return cp
}

func (s *State) recomputeGroupCountsLocked() {
	for _, g := range s.groupList {
		g.UserCount = len(s.groupMembers[g.UUID])
	}
}

func copyPermission(p *Permission) Permission {
	cp := *p
	cp.Actions = slices.Clone(p.Actions)
	cp.Objects = slices.Clone(p.Objects)
	cp.Subjects = slices.Clone(p.Subjects)
	return cp
}

// newDeterministicUUID builds a stable, valid-looking UUID from a label + id
// so seed data and CreateUser stay reproducible without an external UUID lib.
func newDeterministicUUID(label string, id int) string {
	_ = label
	return formatUUID(id)
}

func formatUUID(n int) string {
	// 00000000-0000-4000-8000-xxxxxxxxxxxx — fixed version/variant bits.
	return "00000000-0000-4000-8000-" + pad12(n)
}

func pad12(n int) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 12)
	for i := 11; i >= 0; i-- {
		buf[i] = hexdigits[n%16]
		n /= 16
	}
	return string(buf)
}
