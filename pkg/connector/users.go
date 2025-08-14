package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
)

type userBuilder struct {
	client    *client.TenableVMClient
	connector *Connector
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	annos, err := o.connector.cacheUsers(ctx)
	if err != nil {
		return nil, "", annos, err
	}

	users := o.connector.cachedUsers

	// Create a slice of resources to hold the user resources
	var resources []*v2.Resource
	for _, user := range users {
		userResource, err := parseIntoUserResource(ctx, user, parentResourceID)
		if err != nil {
			return nil, "", nil, err
		}
		resources = append(resources, userResource)
	}
	return resources, "", nil, nil
}

// Entitlements always returns an empty slice for users.
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func parseIntoUserResource(_ context.Context, user *client.User, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var (
		userStatus  = v2.UserTrait_Status_STATUS_ENABLED
		firstName   string
		lastName    string
		displayName string
	)

	profile := map[string]interface{}{
		"user_id":  user.ID,
		"uuid":     user.UUID,
		"username": user.Username,
		"email":    user.Email,
	}

	if user.Name != "" {
		firstName, lastName = getFirstNameAndLastName(user.Name)
		displayName = user.Name
	} else {
		displayName = user.Username
	}

	if firstName != "" {
		profile["first_name"] = firstName
	}
	if lastName != "" {
		profile["last_name"] = lastName
	}

	if !user.Enabled {
		userStatus = v2.UserTrait_Status_STATUS_DISABLED
	}

	userTraits := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
		resource.WithStatus(userStatus),
		resource.WithEmail(user.Email, true),
		resource.WithUserLogin(user.Username),
	}

	if user.LastLogin > 0 {
		lastLoginTime := time.UnixMilli(user.LastLogin)
		userTraits = append(userTraits, resource.WithLastLogin(lastLoginTime))
	}

	ret, err := resource.NewUserResource(
		displayName,
		userResourceType,
		user.ID,
		userTraits,
		resource.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Split the name into first and last name.
func getFirstNameAndLastName(name string) (string, string) {
	parts := strings.Split(name, " ")
	if len(parts) == 0 {
		return "", ""
	}
	firstName := parts[0]
	lastName := ""
	if len(parts) > 1 {
		lastName = strings.Join(parts[1:], " ")
	}
	return firstName, lastName
}

// Account provisioning.
func (b *userBuilder) CreateAccountCapabilityDetails(
	_ context.Context,
) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
	}, nil, nil
}

func (o *userBuilder) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.CredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	profile := accountInfo.GetProfile().AsMap()

	email, ok := profile["email"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing or invalid 'email' in profile")
	}
	name, ok := profile["name"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing or invalid 'name' in profile")
	}

	generatedPassword, err := generateCredentials(credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	userToCreate := client.NewUser{
		Username:    email,
		Password:    generatedPassword,
		Permissions: BasicUserRole,
		Email:       email,
		Name:        name,
	}
	createdUser, err := o.client.CreateUser(ctx, userToCreate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create user: %w", err)
	}

	userResource, err := parseIntoUserResource(ctx, createdUser, nil)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build resource: %w", err)
	}
	caResponse := &v2.CreateAccountResponse_SuccessResult{
		Resource: userResource,
	}

	passResult := &v2.PlaintextData{
		Name:  "password",
		Bytes: []byte(userToCreate.Password),
	}

	return caResponse, []*v2.PlaintextData{passResult}, nil, nil
}

// This will actually just disable the user instead of deleting them.
// Tenable needs to transfer a user's ownership of resources before deleting them to avoid orphaned resources.
// For this reason its common practice to disable the user instead of deleting them.
// https://developer.tenable.com/reference/users-enabled
func (o *userBuilder) Delete(ctx context.Context, principal *v2.ResourceId) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	userID := principal.Resource

	updatedUser, err := o.client.DisableUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("baton-tenable-vm: failed to disable user: %w", err)
	}
	if updatedUser != nil && updatedUser.Enabled {
		l.Error("baton-tenable-vm: disable action error, user is still enabled", zap.String("user_id", userID))
		return nil, status.Errorf(codes.Unknown, "baton-tenable-vm: disable user returned success but user %s is still enabled", userID)
	}

	l.Info("baton-tenable-vm: user disabled successfully", zap.String("user_id", userID))
	return nil, nil
}

func newUserBuilder(c *client.TenableVMClient, con *Connector) *userBuilder {
	return &userBuilder{
		client:    c,
		connector: con,
	}
}
