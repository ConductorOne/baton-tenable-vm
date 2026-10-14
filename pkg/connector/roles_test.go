package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
)

const (
	testAdminRoleUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	testBasicRoleUUID = "c3d4e5f6-a7b8-9012-cdef-234567890abc"
)

type fakeTenable struct {
	userRole   string
	roleWrites [][]string
}

func (f *fakeTenable) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/1001", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1001, "uuid": testUserUUID})
	})
	mux.HandleFunc("GET /access-control/v1/users/{uuid}/roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"user_uuid": testUserUUID, "role_uuids": []string{f.userRole}})
	})
	mux.HandleFunc("PUT /access-control/v1/users/{uuid}/roles", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RoleUUIDs []string `json:"role_uuids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.roleWrites = append(f.roleWrites, body.RoleUUIDs)
		f.userRole = body.RoleUUIDs[0]
		_ = json.NewEncoder(w).Encode(map[string]any{"user_uuid": testUserUUID, "role_uuids": body.RoleUUIDs})
	})
	mux.HandleFunc("GET /access-control/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"uuid": testAdminRoleUUID, "name": "Administrator", "type": "STANDARD"},
			{"uuid": "d4e5f6a7-b8c9-0123-def4-567890abcdef", "name": basicRoleName, "type": "CUSTOM"},
			{"uuid": testBasicRoleUUID, "name": basicRoleName, "type": "STANDARD"},
		})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	})
}

func revokeRole(t *testing.T, f *fakeTenable, roleUUID string) error {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	ctx := context.Background()
	c, err := client.NewClient(ctx, "ak", "sk", srv.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	grant := v2.Grant_builder{
		Principal: v2.Resource_builder{
			Id: v2.ResourceId_builder{ResourceType: userResourceType.Id, Resource: "1001"}.Build(),
		}.Build(),
		Entitlement: v2.Entitlement_builder{
			Resource: v2.Resource_builder{
				Id: v2.ResourceId_builder{ResourceType: roleResourceType.Id, Resource: roleUUID}.Build(),
			}.Build(),
		}.Build(),
	}.Build()
	_, err = newRoleBuilder(c, nil).Revoke(ctx, grant)
	return err
}

// Tenable allows exactly one role per user, so revoke must move the user to the
// built-in Basic role through role_uuids rather than leave the role in place.
func TestRevoke_ReassignsBuiltInBasicRole(t *testing.T) {
	f := &fakeTenable{userRole: testAdminRoleUUID}
	if err := revokeRole(t, f, testAdminRoleUUID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(f.roleWrites) != 1 || len(f.roleWrites[0]) != 1 || f.roleWrites[0][0] != testBasicRoleUUID {
		t.Fatalf("role writes = %v, want one write of [%s]", f.roleWrites, testBasicRoleUUID)
	}

	if err := revokeRole(t, f, testAdminRoleUUID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if len(f.roleWrites) != 1 {
		t.Fatalf("second revoke wrote roles again: %v", f.roleWrites)
	}
}

func TestRevoke_RefusesBasicRole(t *testing.T) {
	f := &fakeTenable{userRole: testBasicRoleUUID}
	err := revokeRole(t, f, testBasicRoleUUID)
	if err == nil || !strings.Contains(err.Error(), "cannot revoke the Basic role") {
		t.Fatalf("revoke err = %v, want the cannot-revoke-Basic error", err)
	}
	if len(f.roleWrites) != 0 {
		t.Fatalf("role writes = %v, want none", f.roleWrites)
	}
}
