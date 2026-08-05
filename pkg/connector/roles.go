package connector

import (
	"context"
	"slices"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	rolePermissionName = "assigned"
	BasicUserRole      = 16
)

type roleBuilder struct {
	client    *client.TenableVMClient
	connector *Connector
}

func (rb *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return roleResourceType
}

func (rb *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	var resources []*v2.Resource

	roles, annos, err := rb.client.GetRoles(ctx)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: annos}, err
	}
	for _, role := range roles {
		newRoleResource, err := parseIntoRoleResource(role, parentResourceID)
		if err != nil {
			l.Debug("Failed to parse into role resource", zap.Any("role", role))
			return nil, &rs.SyncOpResults{Annotations: annos}, err
		}
		resources = append(resources, newRoleResource)
	}
	return resources, &rs.SyncOpResults{Annotations: annos}, nil
}

func (o *roleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var roleEntitlements []*v2.Entitlement

	assigmentOptions := []entitlement.EntitlementOption{
		entitlement.WithGrantableTo(userResourceType),
		entitlement.WithDescription(resource.Description),
		entitlement.WithDisplayName(resource.DisplayName),
	}

	roleEntitlements = append(roleEntitlements, entitlement.NewPermissionEntitlement(resource, rolePermissionName, assigmentOptions...))

	return roleEntitlements, &rs.SyncOpResults{}, nil
}

// Grants returns empty: role assignments are emitted from userBuilder.Grants
// because Tenable has no members-per-role endpoint (roles live on the user).
func (rb *roleBuilder) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, &rs.SyncOpResults{}, nil
}

func parseIntoRoleResource(role *client.RoleDetails, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	stringUUID := role.UUID.String()
	rolePermissions := strings.Join(role.Permissions, ",")
	profile := map[string]any{
		fieldUUID:     stringUUID,
		fieldName:     role.Name,
		"description": role.Description,
		"type":        role.Type,
		"status":      role.Status,
		"permissions": rolePermissions,
	}
	resourceTraitOps := []rs.ResourceOption{
		rs.WithResourceProfile(profile),
	}
	if parentResourceID != nil {
		resourceTraitOps = append(resourceTraitOps, rs.WithParentResourceID(parentResourceID))
	}
	return rs.NewRoleResource(
		role.Name,
		roleResourceType,
		stringUUID,
		nil,
		resourceTraitOps...,
	)
}

func (rb *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (
	annotations.Annotations,
	error,
) {
	l := ctxzap.Extract(ctx)
	userId := principal.Id.Resource
	roleId := entitlement.Resource.Id.Resource

	user, err := rb.client.GetUserDetails(ctx, userId)
	if err != nil {
		l.Debug("Error while getting user details", zap.Error(err))
		return nil, err
	}
	userRoles, err := rb.client.GetUserRoles(ctx, user.UUID)

	if err != nil {
		l.Debug("Error while getting user roles", zap.Error(err))
		return nil, err
	}

	if slices.Contains(userRoles.RolesUUID, roleId) {
		err = rb.connector.reEnableUserIfNeeded(ctx, user, "role")
		if err != nil {
			return nil, err
		}
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	_, err = rb.client.UpdateUserRoles(ctx, user.UUID, roleId)
	if err != nil {
		l.Debug("Error while updating user role",
			zap.String("role id", roleId),
			zap.Any("user uuid", user.UUID),
			zap.Error(err))
		return nil, err
	}

	err = rb.connector.reEnableUserIfNeeded(ctx, user, "role")
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (rb *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (
	annotations.Annotations,
	error,
) {
	l := ctxzap.Extract(ctx)
	userId := grant.Principal.Id.Resource
	roleId := grant.Entitlement.Resource.Id.Resource
	user, err := rb.client.GetUserDetails(ctx, userId)
	if err != nil {
		l.Debug("Error while getting user details", zap.Error(err))
		return nil, err
	}
	userRoles, err := rb.client.GetUserRoles(ctx, user.UUID)

	if err != nil {
		l.Debug("Error while getting user roles", zap.Error(err))
		return nil, err
	}

	if !slices.Contains(userRoles.RolesUUID, roleId) {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	updateUser := client.UserUpdateReqBody{
		Permissions: BasicUserRole,
	}

	updatedUser, err := rb.client.UpdateUser(ctx, userId, updateUser)
	if err != nil {
		l.Debug("Error while updating user role",
			zap.String("role id", roleId),
			zap.Any("user uuid", user.UUID),
			zap.Error(err))
		return nil, err
	}

	l.Debug("User updated successfully",
		zap.String("Name", updatedUser.Name),
		zap.String("Email", updatedUser.Email),
		zap.Int("Permissions", updatedUser.Permissions),
		zap.Bool("Name", updatedUser.Enabled),
	)

	return nil, nil
}

func newRoleBuilder(c *client.TenableVMClient, conn *Connector) *roleBuilder {
	return &roleBuilder{
		client:    c,
		connector: conn,
	}
}
