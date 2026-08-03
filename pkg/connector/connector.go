package connector

import (
	"context"
	"fmt"
	"io"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-tenable-vm/pkg/client"
	cfg "github.com/conductorone/baton-tenable-vm/pkg/config"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var _ connectorbuilder.ConnectorBuilderV2 = (*Connector)(nil)

type Connector struct {
	client            *client.TenableVMClient
	enableOnProvision bool
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newUserBuilder(d.client, d),
		newRoleBuilder(d.client, d),
		newGroupBuilder(d.client, d),
		newPermissionBuilder(d.client, d),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (d *Connector) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Tenable VM",
		Description: "Connector syncing Tenable VM user and role data",
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				fieldName: {
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

// reEnableUserIfNeeded is a helper function that re-enables a user if they are disabled and enableOnProvision is true.
func (c *Connector) reEnableUserIfNeeded(ctx context.Context, user *client.User, operationType string) error {
	if user != nil && !user.Enabled && c.enableOnProvision {
		l := ctxzap.Extract(ctx)
		userId := strconv.Itoa(user.ID)
		_, err := c.client.EnableUser(ctx, userId)
		if err != nil {
			l.Error("Error while re-enabling user", zap.Error(err), zap.String(fieldUserID, userId))
			return fmt.Errorf("%s granted but failed to re-enable user: %w", operationType, err)
		}
	}
	return nil
}

// New returns a new instance of the connector. It matches the signature expected
// by config.RunConnector (cli.NewConnector), returning a ConnectorBuilderV2.
func New(ctx context.Context, connectorConfig *cfg.TenableVm, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	baseURL := connectorConfig.BaseUrl
	if baseURL == "" {
		baseURL = client.BaseURL
	}

	c, err := client.NewClient(ctx, connectorConfig.AccessKey, connectorConfig.SecretKey, baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-tenable-vm: failed to create client: %w", err)
	}
	return &Connector{
		client:            c,
		enableOnProvision: connectorConfig.EnableOnProvision,
	}, nil, nil
}
