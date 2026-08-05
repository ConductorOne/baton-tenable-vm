package connector

import (
	"context"
	"fmt"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const memberEntitlement = "member"

type groupBuilder struct {
	client    *client.TenableVMClient
	connector *Connector
}

func (o *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return groupResourceType
}

func (o *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	groups, annos, err := o.client.GetGroups(ctx)
	if err != nil {
		return nil, &rs.SyncOpResults{Annotations: annos}, err
	}

	var resources []*v2.Resource
	for _, group := range groups {
		groupResource, err := parseIntoGroupResource(ctx, &group, parentResourceID)
		if err != nil {
			return nil, &rs.SyncOpResults{Annotations: annos}, err
		}
		resources = append(resources, groupResource)
	}
	return resources, &rs.SyncOpResults{Annotations: annos}, nil
}

func (o *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
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

	return entitlements, &rs.SyncOpResults{}, nil
}

func (o *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)
	groupId := resource.Id.Resource
	members, annos, err := o.client.GetGroupMembers(ctx, groupId)
	if err != nil {
		l.Debug("Failed to get group members: ", zap.Error(err))
		return nil, &rs.SyncOpResults{Annotations: annos}, err
	}
	for _, member := range members {
		userResourceID := &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     strconv.Itoa(member.ID),
		}
		grant := grant.NewGrant(resource, memberEntitlement, userResourceID)
		grants = append(grants, grant)
	}
	return grants, &rs.SyncOpResults{Annotations: annos}, nil
}

func parseIntoGroupResource(_ context.Context, group *client.Group, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]any{
		fieldName:        group.Name,
		"id":             group.ID,
		"UUID":           group.UUID,
		"container_uuid": group.ContainerUUID,
		"users_count":    group.UsersCount,
	}

	options := []rs.ResourceOption{
		rs.WithResourceProfile(profile),
	}
	if parentResourceID != nil {
		options = append(options, rs.WithParentResourceID(parentResourceID))
	}

	resource, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		nil,
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
			zap.String(fieldUserID, userId),
			zap.String("group_id", groupId),
		)
		return annos, err
	}

	for _, member := range members {
		memberId := strconv.Itoa(member.ID)
		if memberId == userId {
			logger.Debug("User is already a group member",
				zap.String(fieldUserID, userId),
				zap.String("group_id", groupId),
			)
			err = g.connector.reEnableUserIfNeeded(ctx, &member, "group membership")
			if err != nil {
				return nil, err
			}
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}
	}

	err = g.client.CreateUserGroupMembership(ctx, groupId, userId, true)
	if err != nil {
		logger.Debug("Failed to add user to group: ",
			zap.Error(err),
			zap.String(fieldUserID, userId),
			zap.String("group_id", groupId),
		)
		return nil, fmt.Errorf("baton-tenable: failed to add user to group: %w", err)
	}

	if g.connector.enableOnProvision {
		user, err := g.client.GetUserDetails(ctx, userId)
		if err != nil {
			logger.Debug("Failed to get user: ", zap.Error(err), zap.String(fieldUserID, userId))
			return nil, fmt.Errorf("baton-tenable: group membership granted but failed to get user status: %w", err)
		}
		err = g.connector.reEnableUserIfNeeded(ctx, user, "group membership")
		if err != nil {
			return nil, err
		}
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
			zap.String(fieldUserID, userId),
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
				zap.String(fieldUserID, userId),
				zap.String("group_id", groupId),
			)
		}
	}

	if !isMember {
		logger.Debug("Group membership grant already revoked",
			zap.String(fieldUserID, userId),
			zap.String("group_id", groupId),
		)
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	err = g.client.DeleteUserGroupMembership(ctx, groupId, userId)
	if err != nil {
		logger.Debug("Failed to remove user from group: ",
			zap.Error(err),
			zap.String(fieldUserID, userId),
			zap.String("group_id", groupId),
		)
		return nil, fmt.Errorf("baton-tenable: failed to remove user from group: %w", err)
	}

	return nil, nil
}

func newGroupBuilder(cli *client.TenableVMClient, con *Connector) *groupBuilder {
	return &groupBuilder{
		client:    cli,
		connector: con,
	}
}
