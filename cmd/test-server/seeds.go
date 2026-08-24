package main

// Fixed seed UUIDs — deterministic so CI grant/revoke tests can hardcode them.
const (
	containerUUID     = "f8973c82-01a7-4aee-9754-4a61e3b3e70e"
	allUsersGroupUUID = "00000000-0000-0000-0000-000000000000"

	roleAdminUUID   = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	roleScanMgrUUID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
	roleBasicUUID   = "c3d4e5f6-a7b8-9012-cdef-234567890abc"
	roleCustomUUID  = "d4e5f6a7-b8c9-0123-def4-567890abcdef"

	userAliceUUID = "11111111-1111-4111-8111-111111111111"
	userBobUUID   = "22222222-2222-4222-8222-222222222222"
	userCarolUUID = "33333333-3333-4333-8333-333333333333"
	userDaveUUID  = "44444444-4444-4444-8444-444444444444"
	userEveUUID   = "55555555-5555-4555-8555-555555555555"
	userFrankUUID = "66666666-6666-4666-8666-666666666666"

	emailAlice = "alice@example.com"
	emailBob   = "bob@example.com"
	emailCarol = "carol@example.com"
	emailDave  = "dave@example.com"
	emailEve   = "eve@example.com"
	emailFrank = "frank@example.com"

	groupEngUUID         = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	groupProductUUID     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	groupOpsUUID         = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	groupContractorsUUID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

	permAssetsUUID    = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	permTagUUID       = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	permAllUsersUUID  = "a0a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0"
	permAllAdminsUUID = "b0b0b0b0-b0b0-4b0b-8b0b-b0b0b0b0b0b0"

	// Subject types documented in the PermissionSubject enum. AllUsers and
	// AllAdmins carry no uuid/name — they are container-wide.
	subjectTypeUser      = "User"
	subjectTypeUserGroup = "UserGroup"
	subjectTypeAllUsers  = "AllUsers"
	subjectTypeAllAdmins = "AllAdmins"

	// Permission action and object-type values, from the permission-create
	// schema: https://developer.tenable.com/reference/io-v3-access-control-permission-create
	actionCanView       = "CanView"
	actionCanScan       = "CanScan"
	actionCanEdit       = "CanEdit"
	objectTypeAllAssets = "AllAssets"

	// createdBySystem is the value Tenable reports for system-generated objects.
	createdBySystem = "System"

	// Last-login timestamps in Unix MILLISECONDS, per the OpenAPI schema.
	// A wrong unit here surfaces as a 1970 or year-56000 date downstream.
	lastLoginAlice = int64(1787000000000)
	lastLoginBob   = int64(1786500000000)
	lastLoginCarol = int64(1780000000000)
	lastLoginEve   = int64(1786900000000)
	lastLoginFrank = int64(1786100000000)

	roleStatusEnabled = "ENABLED"
	roleTypeStandard  = "STANDARD"
	roleTypeCustom    = "CUSTOM"
	roleNameBasic     = "Basic"
	permVulnRead      = "TIO_BACKEND.VULNERABILITY.READ"
)

func seed(s *State) {
	roles := []*Role{
		{
			UUID: roleAdminUUID, Name: "Administrator", Type: roleTypeStandard, Status: roleStatusEnabled,
			Description: "Full administrative access to all features.",
			RolePermissionStrings: []string{
				"TIO_BACKEND.ACCESS_CONTROL.MANAGE",
				"TIO_BACKEND.SCAN.MANAGE",
			},
		},
		{
			UUID: roleScanMgrUUID, Name: "Scan Manager", Type: roleTypeStandard, Status: roleStatusEnabled,
			Description: "Manage scans and view vulnerabilities.",
			RolePermissionStrings: []string{
				"TIO_BACKEND.SCAN.MANAGE",
				permVulnRead,
			},
		},
		{
			UUID: roleBasicUUID, Name: roleNameBasic, Type: roleTypeStandard, Status: roleStatusEnabled,
			Description: "Read-only basic access.",
			RolePermissionStrings: []string{
				permVulnRead,
			},
		},
		{
			UUID: roleCustomUUID, Name: "Security Analyst", Type: roleTypeCustom, Status: roleStatusEnabled,
			Description: "Custom role for security analysts.",
			RolePermissionStrings: []string{
				permVulnRead,
				"TIO_BACKEND.ASSET.READ",
			},
		},
	}
	for _, r := range roles {
		cp := *r
		s.roles[r.UUID] = &cp
		s.roleList = append(s.roleList, &cp)
	}

	groups := []*Group{
		// The default All Users group is immutable and membership-fixed per the
		// OpenAPI schema; add/remove against it is rejected by the handlers.
		{
			UUID: allUsersGroupUUID, ID: 0, Name: "All Users", ContainerUUID: containerUUID,
			Immutable: true, MembershipFixed: true,
		},
		{UUID: groupEngUUID, ID: 101, Name: "Engineering", ContainerUUID: containerUUID},
		{UUID: groupProductUUID, ID: 102, Name: "Product", ContainerUUID: containerUUID},
		{UUID: groupOpsUUID, ID: 103, Name: "Operations", ContainerUUID: containerUUID},
		// Deliberately empty — exercises groupBuilder.Grants() with zero members.
		{UUID: groupContractorsUUID, ID: 104, Name: "Contractors", ContainerUUID: containerUUID},
	}
	for _, g := range groups {
		cp := *g
		s.groups[g.UUID] = &cp
		s.groupsByID[g.ID] = &cp
		s.groupList = append(s.groupList, &cp)
	}

	users := []*User{
		{
			UUID: userAliceUUID, ID: 1001, Username: emailAlice, Email: emailAlice,
			Name: "Alice Admin", Permissions: 64, Enabled: true, ContainerUUID: containerUUID,
			LastLogin:  lastLoginAlice,
			GroupUUIDs: []string{allUsersGroupUUID, groupEngUUID},
			RbacRoles:  []RbacRole{{UUID: roleAdminUUID, Name: "Administrator"}},
		},
		{
			UUID: userBobUUID, ID: 1002, Username: emailBob, Email: emailBob,
			Name: "Bob Builder", Permissions: 40, Enabled: true, ContainerUUID: containerUUID,
			LastLogin:  lastLoginBob,
			GroupUUIDs: []string{allUsersGroupUUID, groupEngUUID, groupProductUUID},
			RbacRoles:  []RbacRole{{UUID: roleScanMgrUUID, Name: "Scan Manager"}},
		},
		{
			// Disabled user — exercises STATUS_DISABLED / enable-on-provision paths.
			UUID: userCarolUUID, ID: 1003, Username: emailCarol, Email: emailCarol,
			Name: "Carol Disabled", Permissions: 16, Enabled: false, ContainerUUID: containerUUID,
			LastLogin:  lastLoginCarol,
			GroupUUIDs: []string{allUsersGroupUUID, groupProductUUID},
			RbacRoles:  []RbacRole{{UUID: roleBasicUUID, Name: roleNameBasic}},
		},
		{
			// No extra groups — empty-grants path for groups. Also the only user
			// with NO lastlogin: the field is omitted entirely, so the connector's
			// `if user.LastLogin > 0` guard must leave WithLastLogin unset rather
			// than emitting a 1970 epoch.
			UUID: userDaveUUID, ID: 1004, Username: emailDave, Email: emailDave,
			Name: "Dave Lonely", Permissions: 16, Enabled: true, ContainerUUID: containerUUID,
			GroupUUIDs: []string{allUsersGroupUUID},
			RbacRoles:  []RbacRole{{UUID: roleBasicUUID, Name: roleNameBasic}},
		},
		{
			UUID: userEveUUID, ID: 1005, Username: emailEve, Email: emailEve,
			Name: "Eve Operator", Permissions: 32, Enabled: true, ContainerUUID: containerUUID,
			LastLogin:  lastLoginEve,
			GroupUUIDs: []string{allUsersGroupUUID, groupOpsUUID},
			RbacRoles:  []RbacRole{{UUID: roleCustomUUID, Name: "Security Analyst"}},
		},
		{
			// No RBAC roles at all — exercises the `len(user.RbacRoles) > 0` branch
			// in parseIntoUserResource, so role_uuids is absent from the profile and
			// userBuilder.Grants() must emit zero role grants for this user.
			UUID: userFrankUUID, ID: 1006, Username: emailFrank, Email: emailFrank,
			Name: "Frank Noroles", Permissions: 16, Enabled: true, ContainerUUID: containerUUID,
			LastLogin:  lastLoginFrank,
			GroupUUIDs: []string{allUsersGroupUUID},
		},
	}
	for _, u := range users {
		cp := *u
		s.users[u.UUID] = &cp
		s.usersByID[u.ID] = &cp
		s.userList = append(s.userList, &cp)
		s.userRoles[u.UUID] = make([]string, 0, len(u.RbacRoles))
		for _, r := range u.RbacRoles {
			s.userRoles[u.UUID] = append(s.userRoles[u.UUID], r.UUID)
		}
	}
	s.nextUserID = 1006

	// Overlapping memberships on purpose. Contractors is deliberately absent —
	// it stays empty so the zero-member grants path is covered.
	s.groupMembers[allUsersGroupUUID] = []string{
		userAliceUUID, userBobUUID, userCarolUUID, userDaveUUID, userEveUUID, userFrankUUID,
	}
	s.groupMembers[groupEngUUID] = []string{userAliceUUID, userBobUUID}
	s.groupMembers[groupProductUUID] = []string{userBobUUID, userCarolUUID}
	s.groupMembers[groupOpsUUID] = []string{userEveUUID}
	s.recomputeGroupCountsLocked()

	perms := []*Permission{
		{
			UUID: permAssetsUUID, Name: "All Assets [CanScan, CanView]",
			Actions: []string{actionCanView, actionCanScan},
			Objects: []PermissionObject{{Type: objectTypeAllAssets}},
			Subjects: []PermissionSubject{
				{Type: subjectTypeUser, UUID: userAliceUUID, Name: emailAlice},
				{Type: subjectTypeUserGroup, UUID: groupEngUUID, Name: "Engineering"},
			},
			CreatedAt: 1648122396493,
			CreatedBy: createdBySystem,
		},
		{
			UUID: permTagUUID, Name: "Tag 'Location:Headquarters' owner permissions",
			Actions: []string{"CanUse", "CanEdit"},
			Objects: []PermissionObject{
				{Type: "Tag", UUID: "e5f6a7b8-c9d0-1234-ef56-7890abcdef12", Name: "Location:Headquarters"},
			},
			Subjects: []PermissionSubject{
				{Type: subjectTypeUser, UUID: userEveUUID, Name: emailEve},
			},
			CreatedAt: 1706909726620,
			CreatedBy: emailEve,
		},
		{
			// Container-wide subject. AllUsers is a documented PermissionSubject
			// enum value carrying no uuid/name. The connector's subject switch
			// handles only User and UserGroup with no default, so this permission
			// is expected to sync with an entitlement and ZERO grants — C1 then
			// reports nobody holding a permission that everybody holds.
			UUID: permAllUsersUUID, Name: "All Assets [CanView] for everyone",
			Actions: []string{actionCanView},
			Objects: []PermissionObject{{Type: objectTypeAllAssets}},
			Subjects: []PermissionSubject{
				{Type: subjectTypeAllUsers},
			},
			CreatedAt: 1706909726620,
			CreatedBy: createdBySystem,
		},
		{
			// AllAdmins is system-generated only, and is the second unhandled
			// subject type. Mixed with a real User subject so the case also shows
			// whether the handled subject still produces its grant alongside the
			// dropped one.
			UUID: permAllAdminsUUID, Name: "Administrative baseline",
			Actions: []string{actionCanView, actionCanEdit},
			Objects: []PermissionObject{{Type: objectTypeAllAssets}},
			Subjects: []PermissionSubject{
				{Type: subjectTypeAllAdmins},
				{Type: subjectTypeUser, UUID: userBobUUID, Name: emailBob},
			},
			CreatedAt: 1706909726620,
			CreatedBy: createdBySystem,
		},
	}
	for _, p := range perms {
		cp := *p
		s.permissions[p.UUID] = &cp
		s.permList = append(s.permList, &cp)
	}
}
