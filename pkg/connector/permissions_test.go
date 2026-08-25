package connector

import (
	"testing"

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
// parseIntoPermissionResource currently handles only User and UserGroup and has
// no default branch, so the two container-wide types are discarded without an
// error. TestParseIntoPermissionResource_DropsContainerWideSubjects pins that
// behaviour so the drop is visible in the suite rather than silent.
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
			testUserUUID: {ID: 1001, UUID: testUserUUID, Name: "Alice Admin"},
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

// TestParseIntoPermissionResource_DropsContainerWideSubjects is a
// CHARACTERIZATION test. It documents current behaviour, not desired behaviour:
// AllUsers and AllAdmins subjects produce no subject IDs at all, so the
// permission syncs with an entitlement and zero grants.
//
// This is tracked as CXH-2305. When that is fixed, this test should FAIL — that
// failure is the signal the fix landed. Invert it then: assert that a
// container-wide subject produces grants for the relevant population (or that
// an explicit, logged limitation is surfaced), rather than deleting the test.
func TestParseIntoPermissionResource_DropsContainerWideSubjects(t *testing.T) {
	usersByUUID, groupsByUUID := testSubjectMaps(t)

	for _, tc := range []struct {
		name        string
		subjectType string
	}{
		{name: "AllUsers", subjectType: "AllUsers"},
		{name: "AllAdmins", subjectType: "AllAdmins"},
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

			if got, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldUserSubjectIDs); ok {
				t.Errorf("CXH-2305 may be fixed: %s is now %q; invert this test", fieldUserSubjectIDs, got)
			}
			if got, ok := rs.GetProfileStringValue(resource.GetProfile(), fieldGroupSubjectIDs); ok {
				t.Errorf("CXH-2305 may be fixed: %s is now %q; invert this test", fieldGroupSubjectIDs, got)
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
