package connector

import (
	"context"
	"fmt"
	"strconv"

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

const memberEntitlement = "member"

type groupBuilder struct {
	client *client.TenableVMClient
}

func (o *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return groupResourceType
}

func (o *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	groups, annos, err := o.client.GetGroups(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	// Create a slice of resources to hold the user resources
	var resources []*v2.Resource
	for _, group := range groups {
		groupResource, err := parseIntoGroupResource(ctx, &group, parentResourceID)
		if err != nil {
			return nil, "", nil, err
		}
		resources = append(resources, groupResource)
	}
	return resources, "", annos, nil
}

func (o *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	displayName := fmt.Sprintf("%s group %s", resource.DisplayName, memberEntitlement)
	descretion := fmt.Sprintf("Member of %s group", resource.DisplayName)
	entitlements := []*v2.Entitlement{
		entitlement.NewAssignmentEntitlement(
			resource,
			memberEntitlement,
			entitlement.WithGrantableTo(userResourceType),
			entitlement.WithDescription(descretion),
			entitlement.WithDisplayName(displayName),
		),
	}

	return entitlements, "", nil, nil
}

func (o *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)
	groupId := resource.Id.Resource
	members, annos, err := o.client.GetGroupMembers(ctx, groupId)
	if err != nil {
		l.Debug("Failed to get group members: ", zap.Error(err))
		return nil, "", annos, err
	}
	for _, member := range members {
		userResourceID := &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     strconv.Itoa(member.ID),
		}
		grant := grant.NewGrant(resource, memberEntitlement, userResourceID)
		grants = append(grants, grant)
	}
	return grants, "", nil, nil
}

func parseIntoGroupResource(_ context.Context, group *client.Group, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"name":           group.Name,
		"id":             group.ID,
		"UUID":           group.UUID,
		"container_uuid": group.ContainerUUID,
		"users_count":    group.UsersCount,
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	var options []rs.ResourceOption
	if parentResourceID != nil {
		options = append(options, rs.WithParentResourceID(parentResourceID))
	}

	resource, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		groupTraitOptions,
		options...,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (g *groupBuilder) Grant(
	ctx context.Context,
	principal *v2.Resource,
	entitlement *v2.Entitlement,
) (
	annotations.Annotations,
	error,
) {
	logger := ctxzap.Extract(ctx)
	userId := principal.Id.Resource
	groupId := entitlement.Resource.Id.Resource

	members, annos, err := g.client.GetGroupMembers(ctx, groupId)
	if err != nil {
		logger.Debug("Failed to add user to group, could not get current memberships: ",
			zap.Error(err),
			zap.String("user_id", userId),
			zap.String("group_id", groupId),
		)
		return annos, err
	}

	for _, member := range members {
		memberId := strconv.Itoa(member.ID)
		if memberId == userId {
			logger.Debug("User is already a group member",
				zap.String("user_id", userId),
				zap.String("group_id", groupId),
			)
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}
	}

	err = g.client.CreateUserGroupMembership(ctx, groupId, userId, true)
	if err != nil {
		logger.Debug("Failed to add user to group: ",
			zap.Error(err),
			zap.String("user_id", userId),
			zap.String("group_id", groupId),
		)
		return nil, fmt.Errorf("baton-tenable: failed to add user to group: %w", err)
	}

	return nil, nil
}

func (g *groupBuilder) Revoke(
	ctx context.Context,
	grant *v2.Grant,
) (
	annotations.Annotations,
	error,
) {
	logger := ctxzap.Extract(ctx)
	userId := grant.Principal.Id.Resource
	groupId := grant.Entitlement.Resource.Id.Resource

	members, annos, err := g.client.GetGroupMembers(ctx, groupId)
	if err != nil {
		logger.Debug("Failed to add user to group, could not get current memberships: ",
			zap.Error(err),
			zap.String("user_id", userId),
			zap.String("group_id", groupId),
		)
		return annos, err
	}

	isMember := false
	for _, member := range members {
		memberId := strconv.Itoa(member.ID)
		if memberId == userId {
			isMember = true
			logger.Debug("User is a group member, revoking grant...",
				zap.String("user_id", userId),
				zap.String("group_id", groupId),
			)
		}
	}

	if !isMember {
		logger.Debug("Group membership grant already revoked",
			zap.String("user_id", userId),
			zap.String("group_id", groupId),
		)
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	err = g.client.DeleteUserGroupMembership(ctx, groupId, userId)
	if err != nil {
		logger.Debug("Failed to remove user from group: ",
			zap.Error(err),
			zap.String("user_id", userId),
			zap.String("group_id", groupId),
		)
		return nil, fmt.Errorf("baton-tenable: failed to remove user from group: %w", err)
	}

	return nil, nil
}

func newGroupBuilder(c *client.TenableVMClient) *groupBuilder {
	return &groupBuilder{
		client: c,
	}
}
