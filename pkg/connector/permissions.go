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
)

type permissionBuilder struct {
	client    *client.TenableVMClient
	connector *Connector
}

func (o *permissionBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return permissionResourceType
}

func (o *permissionBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	permissions, annos, err := o.client.ListPermissions(ctx)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: annos}, fmt.Errorf("baton-tenable-vm: failed to load permissions: %w", err)
	}
	var resources []*v2.Resource
	for i := range permissions {
		permissionResource, err := parseIntoPermissionResource(&permissions[i], parentResourceID)
		if err != nil {
			return nil, &rs.SyncOpResults{Annotations: annos}, err
		}
		resources = append(resources, permissionResource)
	}
	return resources, &rs.SyncOpResults{Annotations: annos}, nil
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

func (o *permissionBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)
	outputAnnos := annotations.New()
	permissionUUID := resource.Id.Resource

	// Resource-side: subjects live on the permission object. Emitting from
	// user/group side is not viable — principals have no permissions list.
	permission, err := o.client.GetPermissionDetails(ctx, permissionUUID)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to get permission details: %w", err)
	}

	// Subjects only carry UUIDs; synced user/group resource IDs are numeric.
	// Resolve via GetUsers/GetGroups (uhttp GET cache covers repeat Grants calls).
	users, annos, err := o.client.GetUsers(ctx)
	outputAnnos.Merge(annos...)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to load users: %w", err)
	}
	usersByUUID := make(map[string]*client.User, len(users))
	for i := range users {
		usersByUUID[users[i].UUID] = &users[i]
	}

	groups, annos, err := o.client.GetGroups(ctx)
	outputAnnos.Merge(annos...)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: outputAnnos}, fmt.Errorf("baton-tenable-vm: failed to load groups: %w", err)
	}
	groupsByUUID := make(map[string]string, len(groups))
	for i := range groups {
		groupsByUUID[groups[i].UUID] = strconv.Itoa(groups[i].ID)
	}

	for _, subject := range permission.Subjects {
		switch subject.Type {
		case subjectTypeUser:
			userResourceID, err := getUserResourceId(subject.UUID.String(), usersByUUID)
			if err != nil {
				l.Debug("Failed to resolve permission user subject", zap.Error(err))
				return nil, &rs.SyncOpResults{Annotations: outputAnnos}, err
			}
			grants = append(grants, grant.NewGrant(resource, assignedEntitlement, userResourceID))
		case subjectTypeGroup:
			groupResourceID, err := getGroupResourceId(subject.UUID.String(), groupsByUUID)
			if err != nil {
				l.Debug("Failed to resolve permission group subject", zap.Error(err))
				return nil, &rs.SyncOpResults{Annotations: outputAnnos}, err
			}
			expandableMsg := &v2.GrantExpandable{
				EntitlementIds: []string{
					fmt.Sprintf("group:%s:member", groupResourceID.Resource),
				},
			}
			grants = append(grants, grant.NewGrant(resource, assignedEntitlement, groupResourceID,
				grant.WithAnnotation(expandableMsg, &v2.GrantImmutable{})))
		}
	}
	return grants, &rs.SyncOpResults{Annotations: outputAnnos}, nil
}

func parseIntoPermissionResource(permission *client.Permission, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	actionList := strings.Join(permission.Actions, " ")
	profile := map[string]any{
		fieldName: permission.Name,
		fieldUUID: permission.UUID.String(),
		"actions": actionList,
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
