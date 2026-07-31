package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

const (
	testAccessKey = "test-access-key"
	testSecretKey = "test-secret-key"
)

type handlers struct {
	state *State
}

// requireAPIKeys validates the X-ApiKeys header Tenable documents.
// Doc URL: https://developer.tenable.com/docs/authorization
// Format: accessKey=ACCESS_KEY;secretKey=SECRET_KEY (space after ';' optional).
func requireAPIKeys(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("X-ApiKeys")
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.")
			return
		}
		accessKey, secretKey, ok := parseAPIKeys(raw)
		if !ok || accessKey != testAccessKey || secretKey != testSecretKey {
			writeError(w, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.")
			return
		}
		next(w, r)
	}
}

// parseAPIKeys splits "accessKey=…; secretKey=…" into its parts.
// Returns ("", "", false) when either key is missing or the header is malformed.
func parseAPIKeys(raw string) (string, string, bool) {
	parts := strings.Split(raw, ";")
	kv := make(map[string]string, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			return "", "", false
		}
		kv[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	accessKey := kv["accessKey"]
	secretKey := kv["secretKey"]
	if accessKey == "" || secretKey == "" {
		return "", "", false
	}
	return accessKey, secretKey, true
}

// Doc URL: https://developer.tenable.com/reference/users-list
func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	withRoles := r.URL.Query().Get("withRoles") == "true"
	users := h.state.ListUsers()
	if !withRoles {
		for i := range users {
			users[i].RbacRoles = nil
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// Doc URL: https://developer.tenable.com/reference/users-details
// GET /users/{user_id} returns the same user object shape as list.
func (h *handlers) getUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	user, ok := h.state.GetUserByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "user not found")
		return
	}
	if r.URL.Query().Get("withRoles") != "true" {
		user.RbacRoles = nil
	}
	writeJSON(w, http.StatusOK, user)
}

// Doc URL: https://developer.tenable.com/reference/users-create
func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Email       string `json:"email"`
		Name        string `json:"name"`
		Permissions int    `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "Bad Request", "username and password are required")
		return
	}
	email := body.Email
	if email == "" {
		email = body.Username
	}
	perms := body.Permissions
	if perms == 0 {
		perms = 16 // Basic role default per docs
	}
	user := h.state.CreateUser(body.Username, email, body.Name, perms)
	writeJSON(w, http.StatusOK, user)
}

// Doc URL: https://developer.tenable.com/reference/users-edit
func (h *handlers) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Permissions int    `json:"permissions"`
		Email       string `json:"email"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	user, ok := h.state.UpdateUser(id, body.Name, body.Permissions, body.Email, body.Enabled)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// Doc URL: https://developer.tenable.com/reference/users-delete
func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	if !h.state.DeleteUser(id) {
		writeError(w, http.StatusNotFound, "Not Found", "user not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Doc URL: https://developer.tenable.com/reference/users-enabled
func (h *handlers) setUserEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	user, ok := h.state.SetUserEnabled(id, body.Enabled)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// Doc URL: https://developer.tenable.com/reference/groups-list
func (h *handlers) listGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"groups": h.state.ListGroups()})
}

// Doc URL: https://developer.tenable.com/reference/groups-list-users
func (h *handlers) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid group id")
		return
	}
	users, ok := h.state.ListGroupMembers(id)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "group not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// Doc URL: https://developer.tenable.com/reference/groups-add-user
func (h *handlers) addGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid group id")
		return
	}
	userID, err := strconv.Atoi(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	_, ok := h.state.AddGroupMember(groupID, userID)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "group or user not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Doc URL: https://developer.tenable.com/reference/groups-delete-user
func (h *handlers) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid group id")
		return
	}
	userID, err := strconv.Atoi(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "invalid user id")
		return
	}
	_, ok := h.state.RemoveGroupMember(groupID, userID)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "group or user not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Doc URL: https://developer.tenable.com/reference/access-control-roles-list
// Response is a raw JSON array — not wrapped in an object.
func (h *handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.state.ListRoles())
}

// Doc URL: https://developer.tenable.com/reference/access-control-users-role-list
func (h *handlers) getUserRoles(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")
	roles, ok := h.state.GetUserRoles(userUUID)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"container_uuid": containerUUID,
		"user_uuid":      userUUID,
		"role_uuids":     roles,
	})
}

// Doc URL: https://developer.tenable.com/reference/access-control-users-role-update
func (h *handlers) updateUserRoles(w http.ResponseWriter, r *http.Request) {
	userUUID := r.PathValue("uuid")
	var body struct {
		RoleUUIDs []string `json:"role_uuids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	if !h.state.SetUserRoles(userUUID, body.RoleUUIDs) {
		writeError(w, http.StatusNotFound, "Not Found", "user or role not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"container_uuid": containerUUID,
		"user_uuid":      userUUID,
		"role_uuids":     body.RoleUUIDs,
	})
}

// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permissions-list
func (h *handlers) listPermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"permissions": h.state.ListPermissions()})
}

// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permissions-details
func (h *handlers) getPermission(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	perm, ok := h.state.GetPermission(uuid)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "permission not found")
		return
	}
	writeJSON(w, http.StatusOK, perm)
}

// Doc URL: https://developer.tenable.com/reference/io-v3-access-control-permission-update
func (h *handlers) updatePermission(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	var body struct {
		Name     string              `json:"name"`
		Actions  []string            `json:"actions"`
		Objects  []PermissionObject  `json:"objects"`
		Subjects []PermissionSubject `json:"subjects"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	perm, ok := h.state.UpdatePermission(uuid, body.Name, body.Actions, body.Objects, body.Subjects)
	if !ok {
		writeError(w, http.StatusNotFound, "Not Found", "permission not found")
		return
	}
	writeJSON(w, http.StatusOK, perm)
}
