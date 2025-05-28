package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
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
	client              *client.TenableVMClient
	connector           *Connector
	permissionsCache    map[string]*client.Permission
	cacheMutex          sync.Mutex
	permissionsLastLoad time.Time
	cachedGroups        map[string]string
	groupsLastLoad      time.Time
	groupsMtx           sync.Mutex
}

func (o *permissionBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return permissionResourceType
}

func (o *permissionBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	annos, err := o.loadPermissionsCache(ctx)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to load permissions cache: %w", err)
	}
	var resources []*v2.Resource
	for _, permission := range o.permissionsCache {
		permissionResource, err := parseIntoPermissionResource(permission, parentResourceID)
		if err != nil {
			return nil, "", nil, err
		}
		resources = append(resources, permissionResource)
	}
	return resources, "", nil, nil
}

func (o *permissionBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
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

	return entitlements, "", nil, nil
}

func (o *permissionBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)
	permissionUUID := resource.Id.Resource
	annos, err := o.loadPermissionsCache(ctx)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to load permissions cache: %w", err)
	}
	permission, ok := o.permissionsCache[permissionUUID]
	if !ok {
		return nil, "", nil, fmt.Errorf("failed to load permission, not found: %w", err)
	}

	annos, err = o.connector.cacheUsers(ctx)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to cache users: %w", err)
	}

	annos, err = o.loadGroupsCache(ctx)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to cache groups: %w", err)
	}
	for _, subject := range permission.Subjects {
		var newGrant *v2.Grant
		switch subject.Type {
		case subjectTypeUser:
			userResourceID, err := getUserResourceId(subject.UUID.String(), o.connector.cachedUsers)
			if err != nil {
				l.Debug("Failed to retrieve user from cache: ", zap.Error(err))
				return nil, "", nil, err
			}
			newGrant = grant.NewGrant(resource, assignedEntitlement, userResourceID)
			grants = append(grants, newGrant)
		case subjectTypeGroup:
			groupResourceID, err := getGroupResourceId(subject.UUID.String(), o.cachedGroups)
			if err != nil {
				l.Debug("Failed to retrieve user from cache: ", zap.Error(err))
				return nil, "", nil, err
			}
			expandableMsg := &v2.GrantExpandable{
				EntitlementIds: []string{
					fmt.Sprintf("group:%s:member", groupResourceID.Resource),
				},
			}
			newGrant = grant.NewGrant(resource, assignedEntitlement, groupResourceID,
				grant.WithAnnotation(expandableMsg, &v2.GrantImmutable{}))
			grants = append(grants, newGrant)
		}
	}
	return grants, "", nil, nil
}

func parseIntoPermissionResource(permission *client.Permission, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	actionList := strings.Join(permission.Actions, " ")
	profile := map[string]interface{}{
		"name":    permission.Name,
		"uuid":    permission.UUID.String(),
		"actions": actionList,
	}

	permissionTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	var options []rs.ResourceOption
	if parentResourceID != nil {
		options = append(options, rs.WithParentResourceID(parentResourceID))
	}

	resource, err := rs.NewRoleResource(
		permission.Name,
		permissionResourceType,
		permission.UUID.String(),
		permissionTraitOptions,
		options...,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (o *permissionBuilder) loadPermissionsCache(ctx context.Context) (annotations.Annotations, error) {
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()

	// If already populated and still valid, skip
	if o.permissionsCache != nil && time.Since(o.permissionsLastLoad) < (TTL*time.Minute) {
		return nil, nil
	}

	permissions, annos, err := o.client.ListPermissions(ctx)
	if err != nil {
		return annos, err
	}

	permissionsMap := make(map[string]*client.Permission)
	for _, permission := range permissions {
		permissionsMap[permission.UUID.String()] = &permission
	}

	o.permissionsCache = permissionsMap
	o.permissionsLastLoad = time.Now()
	return nil, nil
}

func (o *permissionBuilder) loadGroupsCache(ctx context.Context) (annotations.Annotations, error) {
	o.groupsMtx.Lock()
	defer o.groupsMtx.Unlock()

	if o.cachedGroups != nil && time.Since(o.groupsLastLoad) < TTL*time.Minute {
		return nil, nil
	}

	groupsToCache := make(map[string]string)
	groups, annos, err := o.client.GetGroups(ctx)
	if err != nil {
		return annos, fmt.Errorf("error creating users cache %w", err)
	}

	for _, group := range groups {
		groupsToCache[group.UUID] = strconv.Itoa(group.ID)
	}

	o.cachedGroups = groupsToCache
	o.groupsLastLoad = time.Now()
	return nil, nil
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
