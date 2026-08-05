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
)

const (
	assignedEntitlement = "assigned"
	subjectTypeUser     = "User"
	subjectTypeGroup    = "UserGroup"
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
	for _, permission := range permissions {
		permissionResource, err := parseIntoPermissionResource(&permission, parentResourceID, usersByUUID, groupsByUUID)
		if err != nil {
			return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to build permission %s: %w", permission.UUID, err)
		}
		resources = append(resources, permissionResource)
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

	return grants, &rs.SyncOpResults{}, nil
}

func parseIntoPermissionResource(
	permission *client.Permission,
	parentResourceID *v2.ResourceId,
	usersByUUID map[string]client.User,
	groupsByUUID map[string]string,
) (*v2.Resource, error) {
	actionList := strings.Join(permission.Actions, " ")
	profile := map[string]any{
		fieldName: permission.Name,
		fieldUUID: permission.UUID.String(),
		"actions": actionList,
	}

	var userIDs, groupIDs []string
	for _, subject := range permission.Subjects {
		switch subject.Type {
		case subjectTypeUser:
			userID, err := getUserResourceId(subject.UUID.String(), usersByUUID)
			if err != nil {
				return nil, err
			}
			userIDs = append(userIDs, userID)
		case subjectTypeGroup:
			groupID, err := getGroupResourceId(subject.UUID.String(), groupsByUUID)
			if err != nil {
				return nil, err
			}
			groupIDs = append(groupIDs, groupID)
		}
	}
	if len(userIDs) > 0 {
		profile[fieldUserSubjectIDs] = strings.Join(userIDs, profileListSeparator)
	}
	if len(groupIDs) > 0 {
		profile[fieldGroupSubjectIDs] = strings.Join(groupIDs, profileListSeparator)
	}

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
		return nil, err
	}

	return resource, nil
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

func newPermissionBuilder(cli *client.TenableVMClient, con *Connector) *permissionBuilder {
	return &permissionBuilder{
		client:    cli,
		connector: con,
	}
}
