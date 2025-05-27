package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
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
	client        *client.TenableVMClient
	roleCache     map[string]RoleMapRegistry
	cacheMutex    sync.Mutex
	cacheLastLoad time.Time
}

func (rb *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return roleResourceType
}

type RoleMapRegistry struct {
	Role  *client.Role
	Users []*client.User
}

// There is no endpoint for roles in the Tenable API. Will list users and get the assigned roles.
func (rb *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var resources []*v2.Resource
	annos, err := rb.loadRoleMapCache(ctx)
	if err != nil {
		l.Debug("Error while listing roles, fail to load role map from user list", zap.Any("error", err))
		return nil, "", annos, err
	}

	for _, roleRegistry := range rb.roleCache {
		role := roleRegistry.Role
		newRoleResource, err := parseIntoRoleResource(role, parentResourceID)
		if err != nil {
			l.Debug("Failed to parse into role resource", zap.Any("role", role))
			return nil, "", nil, err
		}
		resources = append(resources, newRoleResource)
	}
	return resources, "", nil, nil
}

func (o *roleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var roleEntitlements []*v2.Entitlement

	assigmentOptions := []entitlement.EntitlementOption{
		entitlement.WithGrantableTo(userResourceType),
		entitlement.WithDescription(resource.Description),
		entitlement.WithDisplayName(resource.DisplayName),
	}

	roleEntitlements = append(roleEntitlements, entitlement.NewPermissionEntitlement(resource, rolePermissionName, assigmentOptions...))

	return roleEntitlements, "", nil, nil
}

func (rb *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)

	annos, err := rb.loadRoleMapCache(ctx)
	if err != nil {
		l.Debug("Error while listing roles, fail to load role map from user list", zap.Any("error", err))
		return nil, "", annos, err
	}

	roleUUID := resource.Id.Resource
	roleRegistry, exists := rb.roleCache[roleUUID]
	if !exists {
		l.Debug("Role resource not found in cache",
			zap.String("role uuid", roleUUID),
			zap.Any("cache", rb.roleCache),
		)
		return nil, "", nil, fmt.Errorf("role resource not found in cache, role uuid: %s", roleUUID)
	}

	for _, user := range roleRegistry.Users {
		userId := &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     strconv.Itoa(user.ID),
		}

		membershipGrant := grant.NewGrant(resource, rolePermissionName, userId)
		grants = append(grants, membershipGrant)
	}

	return grants, "", nil, nil
}

func (o *roleBuilder) loadRoleMapCache(ctx context.Context) (annotations.Annotations, error) {
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()

	// If already populated and still valid, skip
	if o.roleCache != nil && time.Since(o.cacheLastLoad) < (TTL*time.Minute) {
		return nil, nil
	}

	users, annos, err := o.client.GetUsers(ctx)
	if err != nil {
		return annos, err
	}

	roleMap := make(map[string]RoleMapRegistry)
	for _, user := range users {
		for _, role := range user.RbacRoles {
			uuidKey := role.UUID.String()
			if _, exists := roleMap[uuidKey]; !exists {
				roleMap[uuidKey] = RoleMapRegistry{
					Role:  &role,
					Users: []*client.User{&user},
				}
			} else {
				existing := roleMap[uuidKey]
				existing.Users = append(existing.Users, &user)
				roleMap[uuidKey] = existing
			}
		}
	}

	o.roleCache = roleMap
	o.cacheLastLoad = time.Now()
	return nil, nil
}

func parseIntoRoleResource(role *client.Role, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	stringUUID := role.UUID.String()
	profile := map[string]interface{}{
		"uuid": stringUUID,
		"name": role.Name,
	}
	roleTraits := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	resourceTraitOps := []rs.ResourceOption{}
	if parentResourceID != nil {
		resourceTraitOps = append(resourceTraitOps, rs.WithParentResourceID(parentResourceID))
	}
	return rs.NewRoleResource(
		role.Name,
		roleResourceType,
		stringUUID,
		roleTraits,
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

func newRoleBuilder(c *client.TenableVMClient) *roleBuilder {
	return &roleBuilder{
		client: c,
	}
}
