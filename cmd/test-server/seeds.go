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

	emailAlice = "alice@example.com"
	emailBob   = "bob@example.com"
	emailCarol = "carol@example.com"
	emailDave  = "dave@example.com"
	emailEve   = "eve@example.com"

	groupEngUUID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	groupProductUUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	groupOpsUUID     = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

	permAssetsUUID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	permTagUUID    = "ffffffff-ffff-4fff-8fff-ffffffffffff"

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
		{UUID: allUsersGroupUUID, ID: 0, Name: "All Users", ContainerUUID: containerUUID},
		{UUID: groupEngUUID, ID: 101, Name: "Engineering", ContainerUUID: containerUUID},
		{UUID: groupProductUUID, ID: 102, Name: "Product", ContainerUUID: containerUUID},
		{UUID: groupOpsUUID, ID: 103, Name: "Operations", ContainerUUID: containerUUID},
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
			GroupUUIDs: []string{allUsersGroupUUID, groupEngUUID},
			RbacRoles:  []RbacRole{{UUID: roleAdminUUID, Name: "Administrator"}},
		},
		{
			UUID: userBobUUID, ID: 1002, Username: emailBob, Email: emailBob,
			Name: "Bob Builder", Permissions: 40, Enabled: true, ContainerUUID: containerUUID,
			GroupUUIDs: []string{allUsersGroupUUID, groupEngUUID, groupProductUUID},
			RbacRoles:  []RbacRole{{UUID: roleScanMgrUUID, Name: "Scan Manager"}},
		},
		{
			// Disabled user — exercises STATUS_DISABLED / enable-on-provision paths.
			UUID: userCarolUUID, ID: 1003, Username: emailCarol, Email: emailCarol,
			Name: "Carol Disabled", Permissions: 16, Enabled: false, ContainerUUID: containerUUID,
			GroupUUIDs: []string{allUsersGroupUUID, groupProductUUID},
			RbacRoles:  []RbacRole{{UUID: roleBasicUUID, Name: roleNameBasic}},
		},
		{
			// No extra groups / no custom roles beyond Basic — empty-grants path for groups.
			UUID: userDaveUUID, ID: 1004, Username: emailDave, Email: emailDave,
			Name: "Dave Lonely", Permissions: 16, Enabled: true, ContainerUUID: containerUUID,
			GroupUUIDs: []string{allUsersGroupUUID},
			RbacRoles:  []RbacRole{{UUID: roleBasicUUID, Name: roleNameBasic}},
		},
		{
			UUID: userEveUUID, ID: 1005, Username: emailEve, Email: emailEve,
			Name: "Eve Operator", Permissions: 32, Enabled: true, ContainerUUID: containerUUID,
			GroupUUIDs: []string{allUsersGroupUUID, groupOpsUUID},
			RbacRoles:  []RbacRole{{UUID: roleCustomUUID, Name: "Security Analyst"}},
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
	s.nextUserID = 1005

	// Overlapping memberships on purpose.
	s.groupMembers[allUsersGroupUUID] = []string{userAliceUUID, userBobUUID, userCarolUUID, userDaveUUID, userEveUUID}
	s.groupMembers[groupEngUUID] = []string{userAliceUUID, userBobUUID}
	s.groupMembers[groupProductUUID] = []string{userBobUUID, userCarolUUID}
	s.groupMembers[groupOpsUUID] = []string{userEveUUID}
	s.recomputeGroupCountsLocked()

	perms := []*Permission{
		{
			UUID: permAssetsUUID, Name: "All Assets [CanScan, CanView]",
			Actions: []string{"CanView", "CanScan"},
			Objects: []PermissionObject{{Type: "AllAssets"}},
			Subjects: []PermissionSubject{
				{Type: "User", UUID: userAliceUUID, Name: emailAlice},
				{Type: "UserGroup", UUID: groupEngUUID, Name: "Engineering"},
			},
			CreatedAt: 1648122396493,
			CreatedBy: "System",
		},
		{
			UUID: permTagUUID, Name: "Tag 'Location:Headquarters' owner permissions",
			Actions: []string{"CanUse", "CanEdit"},
			Objects: []PermissionObject{
				{Type: "Tag", UUID: "e5f6a7b8-c9d0-1234-ef56-7890abcdef12", Name: "Location:Headquarters"},
			},
			Subjects: []PermissionSubject{
				{Type: "User", UUID: userEveUUID, Name: emailEve},
			},
			CreatedAt: 1706909726620,
			CreatedBy: emailEve,
		},
	}
	for _, p := range perms {
		cp := *p
		s.permissions[p.UUID] = &cp
		s.permList = append(s.permList, &cp)
	}
}
