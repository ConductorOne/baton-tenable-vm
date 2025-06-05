package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

const (
	BaseURL                 = "https://cloud.tenable.com"
	BaseUsersPath           = "/users"
	UserPath                = "/users/%s" // uses user id
	ListGroupsPath          = "/groups"
	ListGroupMembersPath    = "/groups/%s/users"
	UserGroupMembershipPath = "/groups/%s/users/%s"
	UserRolePath            = "/access-control/v1/users/%s/roles" // uses user uuid, not id
	RolesPath               = "/access-control/v1/roles"
	PermissionsPath         = "/api/v3/access-control/permissions"
)

type TenableVMClient struct {
	httpClient *uhttp.BaseHttpClient
	accessKey  string
	secretKey  string
}

type ReqOpt func(reqURL *url.URL)

func NewClient(ctx context.Context, accessKey, secretKey string) (*TenableVMClient, error) {
	client := &TenableVMClient{
		httpClient: &uhttp.BaseHttpClient{},
		accessKey:  accessKey,
		secretKey:  secretKey,
	}
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}
	cli, err := uhttp.NewBaseHttpClientWithContext(context.Background(), httpClient)
	if err != nil {
		return nil, err
	}
	client.httpClient = cli

	return client, nil
}

// API pagination support is limited to specific endpoints.
// As per documentation https://developer.tenable.com/reference/users-list does not include pagination.
func (c *TenableVMClient) GetUsers(ctx context.Context) ([]User, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var res UsersResponse

	queryUrl, err := url.JoinPath(BaseURL, BaseUsersPath)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, nil, err
	}
	annos, err := c.getResourcesFromAPI(ctx, queryUrl, &res, withRoles())
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return nil, annos, err
	}

	return res.Users, annos, nil
}

func (c *TenableVMClient) GetUserDetails(ctx context.Context, userId string) (*User, error) {
	var user User

	queryUrl, err := url.JoinPath(BaseURL, fmt.Sprintf(UserPath, userId))
	if err != nil {
		return nil, fmt.Errorf("error creating url: %w", err)
	}
	_, err = c.getResourcesFromAPI(ctx, queryUrl, &user, withRoles())
	if err != nil {
		return nil, fmt.Errorf("error getting user details resource: %w", err)
	}

	return &user, nil
}

func (c *TenableVMClient) GetRoles(ctx context.Context) ([]*RoleDetails, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var res []*RoleDetails

	queryUrl, err := url.JoinPath(BaseURL, RolesPath)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, nil, err
	}

	annos, err := c.getResourcesFromAPI(ctx, queryUrl, &res)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return nil, annos, err
	}

	return res, annos, nil
}

func (c *TenableVMClient) GetUserRoles(ctx context.Context, userUUID string) (*UserRole, error) {
	var userRoles UserRole

	queryUrl, err := url.JoinPath(BaseURL, fmt.Sprintf(UserRolePath, userUUID))
	if err != nil {
		return nil, fmt.Errorf("error creating url: %w", err)
	}
	_, err = c.getResourcesFromAPI(ctx, queryUrl, &userRoles)
	if err != nil {
		return nil, fmt.Errorf("error getting user details resource: %w", err)
	}

	return &userRoles, nil
}

func (c *TenableVMClient) UpdateUser(ctx context.Context, userId string, body UserUpdateReqBody) (*User, error) {
	var user User

	queryUrl, err := url.JoinPath(BaseURL, fmt.Sprintf(UserPath, userId))
	if err != nil {
		return nil, fmt.Errorf("error creating url: %w", err)
	}
	_, _, err = c.doRequest(ctx, http.MethodPut, queryUrl, &user, body)
	if err != nil {
		return nil, fmt.Errorf("error updating user role: %w", err)
	}

	return &user, nil
}

func (c *TenableVMClient) UpdateUserRoles(ctx context.Context, userUUID string, roleUUID string) (*UserRole, error) {
	var userRoles UserRole

	queryUrl, err := url.JoinPath(BaseURL, fmt.Sprintf(UserRolePath, userUUID))
	if err != nil {
		return nil, fmt.Errorf("error creating url: %w", err)
	}
	body := UserRoleReqBody{RolesUUIDs: []string{roleUUID}}
	_, _, err = c.doRequest(ctx, http.MethodPut, queryUrl, userRoles, body)
	if err != nil {
		return nil, fmt.Errorf("error updating user role: %w", err)
	}

	return &userRoles, nil
}

func (c *TenableVMClient) CreateUser(ctx context.Context, newUser NewUser) (*User, error) {
	var user User

	queryUrl, err := url.JoinPath(BaseURL, BaseUsersPath)
	if err != nil {
		return nil, fmt.Errorf("error creating url: %w", err)
	}

	_, _, err = c.doRequest(ctx, http.MethodPost, queryUrl, &user, newUser)
	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return &user, nil
}

func (c *TenableVMClient) GetGroups(ctx context.Context) ([]Group, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var res GroupsResponse

	queryUrl, err := url.JoinPath(BaseURL, ListGroupsPath)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, nil, err
	}

	annotations, err := c.getResourcesFromAPI(ctx, queryUrl, &res)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return nil, annotations, err
	}

	return res.Groups, annotations, nil
}

func (c *TenableVMClient) GetGroupMembers(ctx context.Context, groupId string) ([]User, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var res UsersResponse

	path := fmt.Sprintf(ListGroupMembersPath, groupId)

	queryUrl, err := url.JoinPath(BaseURL, path)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, nil, err
	}

	annos, err := c.getResourcesFromAPI(ctx, queryUrl, &res)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return nil, annos, err
	}

	return res.Users, nil, nil
}

func (c *TenableVMClient) DeleteUserGroupMembership(ctx context.Context, groupId string, userId string) error {
	l := ctxzap.Extract(ctx)
	path := fmt.Sprintf(UserGroupMembershipPath, groupId, userId)

	queryUrl, err := url.JoinPath(BaseURL, path)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return err
	}

	_, _, err = c.doRequest(ctx, http.MethodDelete, queryUrl, nil, nil)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return err
	}

	return nil
}

func (c *TenableVMClient) CreateUserGroupMembership(ctx context.Context, groupId string, userId string, add bool) error {
	l := ctxzap.Extract(ctx)
	path := fmt.Sprintf(UserGroupMembershipPath, groupId, userId)
	queryUrl, err := url.JoinPath(BaseURL, path)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return err
	}
	_, _, err = c.doRequest(ctx, http.MethodPost, queryUrl, nil, nil)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return err
	}

	return nil
}

func (c *TenableVMClient) ListPermissions(ctx context.Context) ([]Permission, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var res PermissionsList

	queryUrl, err := url.JoinPath(BaseURL, PermissionsPath)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, nil, err
	}

	annos, err := c.getResourcesFromAPI(ctx, queryUrl, &res)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return nil, annos, err
	}

	return res.Permissions, annos, nil
}

func (c *TenableVMClient) GetPermissionDetails(ctx context.Context, uuid string) (*Permission, error) {
	l := ctxzap.Extract(ctx)
	var res Permission

	queryUrl, err := url.JoinPath(BaseURL, PermissionsPath, uuid)
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return nil, err
	}

	_, err = c.getResourcesFromAPI(ctx, queryUrl, &res)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting permission resource: %s", err))
		return nil, err
	}

	return &res, nil
}

func (c *TenableVMClient) UpdatePermission(ctx context.Context, updatedPermission *Permission) error {
	l := ctxzap.Extract(ctx)

	permissionBody := PermissionUpdateBody{
		Name:     updatedPermission.Name,
		Actions:  updatedPermission.Actions,
		Objects:  parseTagNames(updatedPermission.Objects),
		Subjects: updatedPermission.Subjects,
	}
	queryUrl, err := url.JoinPath(BaseURL, PermissionsPath, updatedPermission.UUID.String())
	if err != nil {
		l.Error(fmt.Sprintf("Error creating url: %s", err))
		return err
	}

	_, _, err = c.doRequest(ctx, http.MethodPut, queryUrl, nil, permissionBody)
	if err != nil {
		l.Error(fmt.Sprintf("Error getting resources: %s", err))
		return err
	}

	return nil
}

func (c *TenableVMClient) getResourcesFromAPI(
	ctx context.Context,
	urlAddress string,
	res any,
	reqOpt ...ReqOpt,
) (annotations.Annotations, error) {
	_, annotation, err := c.doRequest(ctx, http.MethodGet, urlAddress, &res, nil, reqOpt...)
	if err != nil {
		return nil, err
	}

	return annotation, nil
}

func (c *TenableVMClient) doRequest(
	ctx context.Context,
	method string,
	endpointUrl string,
	res interface{},
	body interface{},
	reqOpt ...ReqOpt,
) (http.Header, annotations.Annotations, error) {
	var (
		resp *http.Response
		err  error
	)

	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return nil, nil, err
	}

	for _, o := range reqOpt {
		o(urlAddress)
	}

	apiKeyHeader := fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey)
	requestOptions := []uhttp.RequestOption{
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithContentTypeJSONHeader(),
		uhttp.WithHeader("X-ApiKeys", apiKeyHeader),
	}
	if body != nil {
		requestOptions = append(requestOptions, uhttp.WithJSONBody(body))
	}

	req, err := c.httpClient.NewRequest(
		ctx,
		method,
		urlAddress,
		requestOptions...,
	)
	if err != nil {
		return nil, nil, err
	}
	var ratelimitData v2.RateLimitDescription
	var doOptions []uhttp.DoOption
	doOptions = append(doOptions, uhttp.WithRatelimitData(&ratelimitData))
	switch method {
	case http.MethodGet, http.MethodPut, http.MethodPost:

		if res != nil {
			doOptions = append(doOptions, uhttp.WithResponse(&res))
		}
		resp, err = c.httpClient.Do(req, doOptions...)

		if resp != nil {
			defer resp.Body.Close()
		}
	case http.MethodDelete:
		resp, err = c.httpClient.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
	}
	if err != nil {
		return nil, nil, err
	}
	annotation := annotations.Annotations{}
	annotation.WithRateLimiting(&ratelimitData)

	return resp.Header, annotation, nil
}
