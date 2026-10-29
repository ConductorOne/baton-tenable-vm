package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	assignedEntitlement = "assigned"
	subjectTypeUser     = "User"
	subjectTypeGroup    = "UserGroup"
	subjectTypeAllUsers = "AllUsers"
	// subjectTypeAllAdmins is the container-wide "all administrators" subject.
	subjectTypeAllAdmins = "AllAdmins"

	// adminUserPermissionLevel is the legacy permission level of the built-in
	// Administrator role in Tenable's permission ladder: Basic 16, Standard 32,
	// Scan Manager 40, Administrator 64. roles.go's BasicUserRole = 16 is the
	// in-repo precedent.
	// https://developer.tenable.com/docs/roles
	adminUserPermissionLevel = 64
)

type permissionBuilder struct {
	client    *client.TenableVMClient
	connector *Connector
}

func (o *permissionBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return permissionResourceType
}

func (o *permissionBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	outputAnnos := annotations.New()

	permissions, annos, err := o.client.ListPermissions(ctx)
	outputAnnos.Merge(annos...)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to load permissions: %w", err)
	}

	// Subjects only carry UUIDs while the synced user/group resource IDs are
	// numeric, so the whole user and group lists are needed to translate them.
	// Resolving here once per sync keeps Grants() free of API calls: the SDK
	// GET cache drops entries above BATON_HTTP_CACHE_MAX_SIZE (5MB by default),
	// so a per-permission lookup re-downloads the user list on large tenants.
	users, annos, err := o.client.GetUsers(ctx)
	outputAnnos.Merge(annos...)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to load users: %w", err)
	}
	usersByUUID := make(map[string]client.User, len(users))
	for _, user := range users {
		usersByUUID[user.UUID] = user
	}

	groups, annos, err := o.client.GetGroups(ctx)
	outputAnnos.Merge(annos...)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to load groups: %w", err)
	}
	groupsByUUID := make(map[string]string, len(groups))
	for _, group := range groups {
		groupsByUUID[group.UUID] = strconv.Itoa(group.ID)
	}

	var resources []*v2.Resource
	// AllAdmins subjects whose expansion came back empty (see
	// parseIntoPermissionResource): the cause is credential-level, so all
	// affected permissions in one List share it and are reported together in
	// a single warn instead of one line per permission.
	var emptyAdminPermNames []string
	for _, permission := range permissions {
		permissionResource, allAdminsExpandedEmpty, err := parseIntoPermissionResource(&permission, parentResourceID, usersByUUID, groupsByUUID)
		if err != nil {
			return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to build permission %s: %w", permission.UUID, err)
		}
		if allAdminsExpandedEmpty {
			emptyAdminPermNames = append(emptyAdminPermNames, permission.Name)
		}
		resources = append(resources, permissionResource)
	}
	if len(emptyAdminPermNames) > 0 {
		// One-shot per List: the permission builder is top-level, so this warn
		// fires once per sync and needs no sampling. Nothing is returned here,
		// so logging does not double-log a returned error.
		// https://developer.tenable.com/reference/users-list
		l := ctxzap.Extract(ctx)
		l.Warn("baton-tenable-vm: AllAdmins permission subjects expanded to zero grants; the users list carried no permissions or rbac_roles, likely because the connector credential lacks the Administrator permission level (64). AllAdmins grants require an API key with Administrator [64] or a role carrying users-read-with-permissions",
			zap.Strings("permissions", emptyAdminPermNames),
		)
	}
	return resources, &rs.SyncOpResults{Annotations: outputAnnos}, nil
}

func (o *permissionBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	displayName := fmt.Sprintf("%s permission %s", resource.DisplayName, assignedEntitlement)
	description := fmt.Sprintf("Permission %s assigned to subject", resource.DisplayName)
	entitlements := []*v2.Entitlement{
		entitlement.NewAssignmentEntitlement(
			resource,
			assignedEntitlement,
			entitlement.WithGrantableTo(userResourceType, groupResourceType),
			entitlement.WithDescription(description),
			entitlement.WithDisplayName(displayName),
		),
	}

	return entitlements, &rs.SyncOpResults{}, nil
}

// Grants emits one grant per subject of the permission. List() already resolved
// the subject UUIDs into synced resource IDs and stored them on the resource, so
// this phase issues no API call at all.
func (o *permissionBuilder) Grants(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var grants []*v2.Grant
	profile := resource.GetProfile()

	if userIDs, ok := rs.GetProfileStringValue(profile, fieldUserSubjectIDs); ok {
		for _, userID := range strings.Split(userIDs, profileListSeparator) {
			userResourceID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: userID}
			grants = append(grants, grant.NewGrant(resource, assignedEntitlement, userResourceID))
		}
	}

	if groupIDs, ok := rs.GetProfileStringValue(profile, fieldGroupSubjectIDs); ok {
		for _, groupID := range strings.Split(groupIDs, profileListSeparator) {
			groupResourceID := &v2.ResourceId{ResourceType: groupResourceType.Id, Resource: groupID}
			expandableMsg := &v2.GrantExpandable{
				EntitlementIds: []string{
					fmt.Sprintf("group:%s:member", groupID),
				},
			}
			grants = append(grants, grant.NewGrant(resource, assignedEntitlement, groupResourceID,
				grant.WithAnnotation(expandableMsg, &v2.GrantImmutable{})))
		}
	}

	// Users expanded from container-wide AllUsers/AllAdmins subjects point at
	// the numeric user resource IDs synced from the same population. They are
	// emitted immutable: Revoke only serves principals whose UUID literally
	// appears in permission.Subjects, so a revocable-looking derived grant would
	// bounce off GrantAlreadyRevoked while the user still holds access.
	if systemUserIDs, ok := rs.GetProfileStringValue(profile, fieldSystemUserSubjectIDs); ok {
		for _, userID := range strings.Split(systemUserIDs, profileListSeparator) {
			userResourceID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: userID}
			grants = append(grants, grant.NewGrant(resource, assignedEntitlement, userResourceID,
				grant.WithAnnotation(&v2.GrantImmutable{})))
		}
	}

	return grants, &rs.SyncOpResults{}, nil
}

func parseIntoPermissionResource(
	permission *client.Permission,
	parentResourceID *v2.ResourceId,
	usersByUUID map[string]client.User,
	groupsByUUID map[string]string,
) (*v2.Resource, bool, error) {
	actionList := strings.Join(permission.Actions, " ")
	profile := map[string]any{
		fieldName: permission.Name,
		fieldUUID: permission.UUID.String(),
		"actions": actionList,
	}

	var userIDs, groupIDs []string
	var systemUserIDs []string
	// allAdminsMatched counts users the AllAdmins expansion accepted before
	// dedup — the expansion's true size. It is kept separate from
	// systemUserIDs because a coexisting AllUsers subject can fill that slice
	// even when zero administrators matched.
	allAdminsSeen, allAdminsMatched := false, 0
	explicitUserSeen := make(map[string]struct{})
	systemUserSeen := make(map[string]struct{})
	for _, subject := range permission.Subjects {
		switch subject.Type {
		case subjectTypeUser:
			userID, err := getUserResourceId(subject.UUID.String(), usersByUUID)
			if err != nil {
				return nil, false, err
			}
			userIDs = append(userIDs, userID)
			explicitUserSeen[userID] = struct{}{}
		case subjectTypeGroup:
			groupID, err := getGroupResourceId(subject.UUID.String(), groupsByUUID)
			if err != nil {
				return nil, false, err
			}
			groupIDs = append(groupIDs, groupID)
		case subjectTypeAllUsers:
			for _, user := range usersByUUID {
				appendSystemUserID(&systemUserIDs, explicitUserSeen, systemUserSeen, strconv.Itoa(user.ID))
			}
		case subjectTypeAllAdmins:
			allAdminsSeen = true
			for _, user := range usersByUUID {
				if isAdminUser(user) {
					allAdminsMatched++
					appendSystemUserID(&systemUserIDs, explicitUserSeen, systemUserSeen, strconv.Itoa(user.ID))
				}
			}
		default:
			return nil, false, fmt.Errorf("baton-tenable-vm: permission %s has unsupported subject type %q", permission.UUID, subject.Type)
		}
	}
	if len(userIDs) > 0 {
		profile[fieldUserSubjectIDs] = strings.Join(userIDs, profileListSeparator)
	}
	if len(groupIDs) > 0 {
		profile[fieldGroupSubjectIDs] = strings.Join(groupIDs, profileListSeparator)
	}
	// Subject order is arbitrary in the payload, so re-dedupe against the FULL
	// explicit user list once the loop is done: a container-wide subject that
	// precedes the explicit User subject must not duplicate its ID either.
	// Sort the result so the profile value is byte-stable across syncs: the
	// expansion iterates a map, so without sorting the joined list would
	// reshuffle on every run.
	filtered := make([]string, 0, len(systemUserIDs))
	for _, id := range systemUserIDs {
		if _, dup := explicitUserSeen[id]; !dup {
			filtered = append(filtered, id)
		}
	}
	systemUserIDs = filtered
	slices.Sort(systemUserIDs)
	if len(systemUserIDs) > 0 {
		profile[fieldSystemUserSubjectIDs] = strings.Join(systemUserIDs, profileListSeparator)
	}

	// An AllAdmins subject against a non-empty user list that matched zero
	// administrators is anomalous: every container carries at least one
	// administrator, so the likely cause is a least-privilege connector
	// credential — Tenable returns permissions and rbac_roles in GET /users
	// only for credentials holding Administrator [64], leaving isAdminUser
	// false for everyone. Reported to List() so the sync stays green (a
	// least-privilege credential must not fail it) while the expansion loss
	// is surfaced in one aggregated warn.
	// https://developer.tenable.com/reference/users-list
	allAdminsExpandedEmpty := allAdminsSeen && allAdminsMatched == 0 && len(usersByUUID) > 0

	options := []rs.ResourceOption{
		rs.WithResourceProfile(profile),
	}
	if parentResourceID != nil {
		options = append(options, rs.WithParentResourceID(parentResourceID))
	}

	resource, err := rs.NewRoleResource(
		permission.Name,
		permissionResourceType,
		permission.UUID.String(),
		nil,
		options...,
	)

	if err != nil {
		return nil, false, err
	}

	return resource, allAdminsExpandedEmpty, nil
}

func (o *permissionBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (
	annotations.Annotations, error,
) {
	if principal.Id.ResourceType != userResourceType.Id {
		return nil, fmt.Errorf("can not grant to resource type %s", principal.Id.ResourceType)
	}
	permissionUUID := entitlement.Resource.Id.Resource
	permission, err := o.client.GetPermissionDetails(ctx, permissionUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission details %w", err)
	}

	user, err := o.client.GetUserDetails(ctx, principal.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("error while performing grant, failed to get user details %w", err)
	}

	for _, subject := range permission.Subjects {
		if subject.UUID.String() == user.UUID {
			err = o.connector.reEnableUserIfNeeded(ctx, user, "permission")
			if err != nil {
				return nil, err
			}
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}
	}

	uuid, err := uuid.Parse(user.UUID)
	if err != nil {
		return nil, fmt.Errorf("error while parsing user uuid %w", err)
	}

	tenableSubject := client.TenableObject{
		Type: subjectTypeUser,
		Name: user.Name,
		UUID: uuid,
	}

	permission.Subjects = append(permission.Subjects, tenableSubject)
	err = o.client.UpdatePermission(ctx, permission)
	if err != nil {
		return nil, fmt.Errorf("failed to update permission %w", err)
	}

	err = o.connector.reEnableUserIfNeeded(ctx, user, "permission")
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (o *permissionBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	principal := grant.Principal
	if principal.Id.ResourceType != userResourceType.Id {
		return nil, fmt.Errorf("can not revoke grant for resource type %s", principal.Id.ResourceType)
	}
	permissionUUID := grant.Entitlement.Resource.Id.Resource
	permission, err := o.client.GetPermissionDetails(ctx, permissionUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission details %w", err)
	}

	user, err := o.client.GetUserDetails(ctx, principal.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("error while revoking grant, failed to get user details %w", err)
	}

	isGranted := false
	for _, subject := range permission.Subjects {
		if subject.UUID.String() == user.UUID {
			isGranted = true
		}
	}
	if !isGranted {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	uuid, err := uuid.Parse(user.UUID)
	if err != nil {
		return nil, fmt.Errorf("error while parsing user uuid %w", err)
	}

	permission.Subjects = slices.DeleteFunc(permission.Subjects, func(obj client.TenableObject) bool {
		return obj.UUID == uuid
	})

	err = o.client.UpdatePermission(ctx, permission)
	if err != nil {
		return nil, fmt.Errorf("failed to update permission %w", err)
	}

	return nil, nil
}

// isAdminUser reports whether a user is an administrator in Tenable's legacy
// permission ladder: either the legacy permission level of the built-in
// Administrator role (64), or a role literally named "Administrator".
//
// Known gaps (CXH-2305, plan D4), deliberately not widened beyond these stable
// identifiers: (a) OVER-COUNT — a custom role named "Administrator" matches the
// name check even if its privileges are weaker, so such a user is counted as an
// admin; (b) UNDER-COUNT — an admin-equivalent custom role with a different
// name and no legacy permission level 64 is missed. A renamed built-in
// Administrator role is still caught by the level-64 half for users carrying it.
func isAdminUser(u client.User) bool {
	return u.Permissions == adminUserPermissionLevel ||
		slices.ContainsFunc(u.RbacRoles, func(r client.Role) bool {
			return r.Name == "Administrator"
		})
}

// appendSystemUserID appends id to *systemUserIDs unless it is already present
// in the permission's explicit user set or already appended. This is the only
// dedup mechanism for container-wide expansions. Set lookups keep expansion
// O(n) over the container population instead of O(n^2) list scans.
func appendSystemUserID(systemUserIDs *[]string, explicitUserSeen, systemUserSeen map[string]struct{}, id string) {
	if _, dup := explicitUserSeen[id]; dup {
		return
	}
	if _, dup := systemUserSeen[id]; dup {
		return
	}
	systemUserSeen[id] = struct{}{}
	*systemUserIDs = append(*systemUserIDs, id)
}

func newPermissionBuilder(cli *client.TenableVMClient, con *Connector) *permissionBuilder {
	return &permissionBuilder{
		client:    cli,
		connector: con,
	}
}
