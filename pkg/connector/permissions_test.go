package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	"github.com/google/uuid"
)

// Tenable's PermissionSubject.type enum declares four values. Doc URL:
// https://developer.tenable.com/reference/io-v3-access-control-permission-create
//
//	User      — a specific user, carries uuid + name
//	UserGroup — a specific group, carries uuid + name
//	AllUsers  — all users in the container, carries neither
//	AllAdmins — all administrators in the container, system-generated only
//
// parseIntoPermissionResource handles all four: User and UserGroup resolve to
// synced resource IDs in fieldUserSubjectIDs / fieldGroupSubjectIDs, while
// AllUsers and AllAdmins expand to the container population in the dedicated
// fieldSystemUserSubjectIDs (CXH-2305). Unknown subject types fail loud.
func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parsing uuid %q: %v", s, err)
	}
	return u
}

const (
	testUserUUID  = "11111111-1111-4111-8111-111111111111"
	testGroupUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testPermUUID  = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func testSubjectMaps(t *testing.T) (map[string]client.User, map[string]string) {
	t.Helper()
	return map[string]client.User{
		// Alice is an administrator (CXH-2305, D7 note 8): legacy permission
		// level 64 AND an RBAC role literally named "Administrator", so the
		// AllAdmins expansion resolves to {1001} and dedups against the
		// explicit User subject in the mixed control.
		testUserUUID: {ID: 1001, UUID: testUserUUID, Name: "Alice Admin", Permissions: 64, RbacRoles: []client.Role{{Name: "Administrator"}}},
	}, map[string]string{
		testGroupUUID: "101",
	}
}

// TestParseIntoPermissionResource_HandledSubjects is the positive control: the
// two subject types the connector implements resolve to synced resource IDs.
func TestParseIntoPermissionResource_HandledSubjects(t *testing.T) {
	usersByUUID, groupsByUUID := testSubjectMaps(t)

	perm := &client.Permission{
		UUID:    mustUUID(t, testPermUUID),
		Name:    "All Assets [CanView]",
		Actions: []string{"CanView"},
		Subjects: []client.TenableObject{
			{Type: subjectTypeUser, UUID: mustUUID(t, testUserUUID), Name: "Alice Admin"},
			{Type: subjectTypeGroup, UUID: mustUUID(t, testGroupUUID), Name: "Engineering"},
		},
	}

	resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
	if err != nil {
		t.Fatalf("parseIntoPermissionResource: %v", err)
	}

	gotUsers, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldUserSubjectIDs)
	if !ok || gotUsers != "1001" {
		t.Errorf("%s = %q (present=%v), want %q", fieldUserSubjectIDs, gotUsers, ok, "1001")
	}

	gotGroups, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldGroupSubjectIDs)
	if !ok || gotGroups != "101" {
		t.Errorf("%s = %q (present=%v), want %q", fieldGroupSubjectIDs, gotGroups, ok, "101")
	}
}

// TestParseIntoPermissionResource_ExpandsContainerWideSubjects pins the
// desired behavior fixed by CXH-2305: a container-wide AllUsers subject
// expands to every user in the resolved user population, and an AllAdmins
// subject expands to every administrator, both into the dedicated
// fieldSystemUserSubjectIDs profile field at parse time (no extra API calls).
// Users/groups explicitly listed as subjects are unaffected: they still land
// in fieldUserSubjectIDs / fieldGroupSubjectIDs only.
func TestParseIntoPermissionResource_ExpandsContainerWideSubjects(t *testing.T) {
	usersByUUID, groupsByUUID := testSubjectMaps(t)

	for _, tc := range []struct {
		name        string
		subjectType string
	}{
		{name: "AllUsers", subjectType: subjectTypeAllUsers},
		{name: "AllAdmins", subjectType: subjectTypeAllAdmins},
	} {
		t.Run(tc.name, func(t *testing.T) {
			perm := &client.Permission{
				UUID:    mustUUID(t, testPermUUID),
				Name:    "All Assets [CanView] for everyone",
				Actions: []string{"CanView"},
				// Container-wide subjects carry no uuid or name, per the schema.
				Subjects: []client.TenableObject{{Type: tc.subjectType}},
			}

			resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
			if err != nil {
				t.Fatalf("parseIntoPermissionResource: %v", err)
			}

			gotSystem, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldSystemUserSubjectIDs)
			if !ok {
				t.Fatalf("%s is absent; container-wide expansion failed", fieldSystemUserSubjectIDs)
			}
			// The only fixture user is Alice (ID 1001), an administrator. Compare
			// as a comma-split SET: the AllUsers/AllAdmins expansion iterates
			// usersByUUID, whose order is nondeterministic.
			gotSet := strings.Split(gotSystem, profileListSeparator)
			wantSet := []string{"1001"}
			sort.Strings(gotSet)
			sort.Strings(wantSet)
			if !slices.Equal(gotSet, wantSet) {
				t.Errorf("%s = %v, want %v", fieldSystemUserSubjectIDs, gotSet, wantSet)
			}
			if got, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldUserSubjectIDs); ok {
				t.Errorf("container-wide-only permission must not populate %s, got %q", fieldUserSubjectIDs, got)
			}
			if got, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldGroupSubjectIDs); ok {
				t.Errorf("container-wide-only permission must not populate %s, got %q", fieldGroupSubjectIDs, got)
			}
		})
	}
}

// TestParseIntoPermissionResource_MixedSubjectsKeepsHandledOnly is the
// discriminator between "the whole permission failed to parse" and "only the
// unhandled subject was dropped". One permission, two subjects, one of each.
func TestParseIntoPermissionResource_MixedSubjectsKeepsHandledOnly(t *testing.T) {
	usersByUUID, groupsByUUID := testSubjectMaps(t)

	perm := &client.Permission{
		UUID:    mustUUID(t, testPermUUID),
		Name:    "Administrative baseline",
		Actions: []string{"CanView", "CanEdit"},
		Subjects: []client.TenableObject{
			{Type: "AllAdmins"},
			{Type: subjectTypeUser, UUID: mustUUID(t, testUserUUID), Name: "Alice Admin"},
		},
	}

	resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
	if err != nil {
		t.Fatalf("parseIntoPermissionResource: %v", err)
	}

	// The handled subject still produces its ID; the unhandled one contributes
	// nothing. If this ever returns more than the single user, CXH-2305 moved.
	gotUsers, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldUserSubjectIDs)
	if !ok || gotUsers != "1001" {
		t.Errorf("%s = %q (present=%v), want %q", fieldUserSubjectIDs, gotUsers, ok, "1001")
	}
}

// TestParseIntoPermissionResource_UnknownSubjectTypeErrors pins the fail-loud
// default: an unrecognized subject type is an error, never a silent drop.
func TestParseIntoPermissionResource_UnknownSubjectTypeErrors(t *testing.T) {
	usersByUUID, groupsByUUID := testSubjectMaps(t)

	perm := &client.Permission{
		UUID:    mustUUID(t, testPermUUID),
		Name:    "Bogus subject",
		Actions: []string{"CanView"},
		Subjects: []client.TenableObject{
			{Type: "BadType"},
		},
	}

	resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
	if err == nil {
		t.Fatalf("expected an error for unsupported subject type, got resource %v", resource)
	}
	for _, want := range []string{"baton-tenable-vm:", "unsupported subject type", `"BadType"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err.Error(), want)
		}
	}
}

// TestParseIntoPermissionResource_DeduplicatesSystemSubjects pins the dedup
// rule: a container-wide expansion never re-appends a user ID already present
// in the permission's explicit User subject list.
func TestParseIntoPermissionResource_DeduplicatesSystemSubjects(t *testing.T) {
	for _, tc := range []struct {
		name        string
		subjectType string
	}{
		{name: "AllUsers", subjectType: subjectTypeAllUsers},
		{name: "AllAdmins", subjectType: subjectTypeAllAdmins},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usersByUUID, groupsByUUID := testSubjectMaps(t)

			perm := &client.Permission{
				UUID:    mustUUID(t, testPermUUID),
				Name:    "Mixed with explicit user",
				Actions: []string{"CanView"},
				Subjects: []client.TenableObject{
					{Type: tc.subjectType},
					{Type: subjectTypeUser, UUID: mustUUID(t, testUserUUID), Name: "Alice Admin"},
				},
			}

			resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
			if err != nil {
				t.Fatalf("parseIntoPermissionResource: %v", err)
			}

			gotUsers, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldUserSubjectIDs)
			if !ok || gotUsers != "1001" {
				t.Errorf("%s = %q (present=%v), want %q", fieldUserSubjectIDs, gotUsers, ok, "1001")
			}
			// Every candidate (Alice, ID 1001) dedups against the explicit list,
			// so the system field stays absent.
			if got, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldSystemUserSubjectIDs); ok {
				t.Errorf("%s = %q, want absent (full dedup against explicit user)", fieldSystemUserSubjectIDs, got)
			}
		})
	}
}

// TestIsAdminUser pins the administrator predicate: legacy permission level 64
// OR an RBAC role literally named "Administrator".
func TestIsAdminUser(t *testing.T) {
	for _, tc := range []struct {
		name string
		user client.User
		want bool
	}{
		{name: "permission level 64", user: client.User{Permissions: 64}, want: true},
		// A renamed built-in Administrator keeps its legacy permission level,
		// so the level disjunct still classifies it (plan T5 row).
		{name: "renamed built-in administrator", user: client.User{Permissions: 64, RbacRoles: []client.Role{{Name: "Super Admin"}}}, want: true},
		{name: "rbac role Administrator", user: client.User{RbacRoles: []client.Role{{Name: "Administrator"}}}, want: true},
		{name: "scan manager 40", user: client.User{Permissions: 40, RbacRoles: []client.Role{{Name: "Scan Manager"}}}, want: false},
		// Current behavior, documented residual gap (CXH-2305 plan D4), not a
		// bug: a role named "Administrator" counts as admin regardless of its
		// actual privilege mapping.
		{name: "custom Administrator role", user: client.User{RbacRoles: []client.Role{{UUID: mustUUID(t, testAdminRoleUUID), Name: "Administrator"}}}, want: true},
		{name: "standard 32", user: client.User{Permissions: 32, RbacRoles: []client.Role{{Name: "Standard"}}}, want: false},
		{name: "basic 16", user: client.User{Permissions: 16}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAdminUser(tc.user); got != tc.want {
				t.Errorf("isAdminUser(%+v) = %v, want %v", tc.user, got, tc.want)
			}
		})
	}
}

// TestGrants_EmitsImmutableGrantsForSystemUserSubjectIDs pins the Grants phase:
// every user ID in fieldSystemUserSubjectIDs becomes one grant whose principal
// is the synced numeric user resource, annotated GrantImmutable (never
// GrantExpandable — Revoke only serves literal subjects, see D6).
func TestGrants_EmitsImmutableGrantsForSystemUserSubjectIDs(t *testing.T) {
	_, groupsByUUID := testSubjectMaps(t)
	usersByUUID := map[string]client.User{
		testUserUUID:                           {ID: 1001, UUID: testUserUUID, Name: "Alice Admin"},
		"22222222-2222-4222-8222-222222222222": {ID: 1002, UUID: "22222222-2222-4222-8222-222222222222", Name: "Bob"},
		"33333333-3333-4333-8333-333333333333": {ID: 1003, UUID: "33333333-3333-4333-8333-333333333333", Name: "Carol"},
	}

	perm := &client.Permission{
		UUID:     mustUUID(t, testPermUUID),
		Name:     "All Assets [CanView] for everyone",
		Actions:  []string{"CanView"},
		Subjects: []client.TenableObject{{Type: subjectTypeAllUsers}},
	}

	resource, err := parseIntoPermissionResource(perm, nil, usersByUUID, groupsByUUID)
	if err != nil {
		t.Fatalf("parseIntoPermissionResource: %v", err)
	}

	grants, _, err := newPermissionBuilder(nil, nil).Grants(context.Background(), resource, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Grants: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("got %d grants, want 3", len(grants))
	}

	wantPrincipals := []string{"1001", "1002", "1003"}
	gotPrincipals := make([]string, 0, len(grants))
	for _, g := range grants {
		if g.Principal.Id.ResourceType != userResourceType.Id {
			t.Errorf("grant principal resource type = %s, want %s", g.Principal.Id.ResourceType, userResourceType.Id)
		}
		gotPrincipals = append(gotPrincipals, g.Principal.Id.Resource)
		a := annotations.Annotations(g.GetAnnotations())
		if !a.Contains(&v2.GrantImmutable{}) {
			t.Errorf("grant for %s missing GrantImmutable annotation", g.Principal.Id.Resource)
		}
		if a.Contains(&v2.GrantExpandable{}) {
			t.Errorf("grant for %s must not contain GrantExpandable", g.Principal.Id.Resource)
		}
	}
	sort.Strings(gotPrincipals)
	if !slices.Equal(gotPrincipals, wantPrincipals) {
		t.Errorf("principals = %v, want %v", gotPrincipals, wantPrincipals)
	}
}

// TestRevoke_ContainerWideDerivedGrantIsNoOp pins the revoke-flap rationale
// (D6): a grant derived from an AllAdmins subject has no literal User subject
// with the principal's UUID, so Revoke must return GrantAlreadyRevoked without
// issuing any UpdatePermission write.
func TestRevoke_ContainerWideDerivedGrantIsNoOp(t *testing.T) {
	var permWrites int
	f := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v3/access-control/permissions/"+testPermUUID, func(w http.ResponseWriter, r *http.Request) {
			// Bare client.Permission shape, same as GetPermissionDetails reads:
			// subjects entries carry only type for container-wide subjects.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"permission_uuid": testPermUUID,
				"name":            "Administrative baseline",
				"actions":         []string{"CanView"},
				"subjects":        []map[string]any{{"type": subjectTypeAllAdmins}},
			})
		})
		mux.HandleFunc("GET /users/1001", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1001, "uuid": testUserUUID})
		})
		mux.HandleFunc("PUT /api/v3/access-control/permissions/"+testPermUUID, func(w http.ResponseWriter, r *http.Request) {
			permWrites++
			_ = json.NewEncoder(w).Encode(map[string]any{})
		})
		mux.ServeHTTP(w, r)
	}

	srv := httptest.NewServer(http.HandlerFunc(f))
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
				Id: v2.ResourceId_builder{ResourceType: permissionResourceType.Id, Resource: testPermUUID}.Build(),
			}.Build(),
		}.Build(),
	}.Build()

	annos, err := newPermissionBuilder(c, nil).Revoke(ctx, grant)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ra := annotations.Annotations(annos)
	if !ra.Contains(&v2.GrantAlreadyRevoked{}) {
		t.Errorf("annotations = %v, want GrantAlreadyRevoked", annos)
	}
	if permWrites != 0 {
		t.Errorf("UpdatePermission called %d times, want 0", permWrites)
	}
}
