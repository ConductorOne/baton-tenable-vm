package connector

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
)

const TTL = 5 // in minutes

type Connector struct {
	client         *client.TenableVMClient
	cachedUsers    map[string]*client.User
	usersTimestamp time.Time
	usersMtx       sync.Mutex
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client, d),
		newRoleBuilder(d.client),
		newGroupBuilder(d.client),
		newPermissionBuilder(d.client, d),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (d *Connector) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

func (c *Connector) cacheUsers(ctx context.Context) (annotations.Annotations, error) {
	c.usersMtx.Lock()
	defer c.usersMtx.Unlock()

	if c.cachedUsers != nil && time.Since(c.usersTimestamp) < TTL*time.Minute {
		return nil, nil
	}

	usersToCache := make(map[string]*client.User)
	users, annos, err := c.client.GetUsers(ctx)
	if err != nil {
		return annos, fmt.Errorf("error creating users cache %w", err)
	}

	for _, user := range users {
		usersToCache[user.UUID] = &user
	}

	c.cachedUsers = usersToCache
	c.usersTimestamp = time.Now()
	return nil, nil
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Tenable VM",
		Description: "Connector syncing Tenable VM user and role data",
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"name": {
					DisplayName: "Name",
					Required:    true,
					Description: "This name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Name",
					Order:       1,
				},
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "This email will be used as the login for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Email",
					Order:       2,
				},
			},
		},
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, accessKey, secretKey string) (*Connector, error) {
	client, err := client.NewClient(ctx, accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return &Connector{
		client: client,
	}, nil
}
