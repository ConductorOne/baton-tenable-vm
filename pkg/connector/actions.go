package connector

import (
	"context"
	"fmt"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

var disableAccountActionSchema = &v2.BatonActionSchema{
	Name: "disable_account",
	Arguments: []*config.Field{
		{
			Name:        "resource_id",
			DisplayName: "User Resource ID",
			Description: "The ID of the user to disable",
			Field:       &config.Field_StringField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        "success",
			DisplayName: "Success",
			Description: "Whether the account was disabled successfully",
			Field:       &config.Field_BoolField{},
		},
	},
}

func (c *Connector) RegisterActionManager(ctx context.Context) (connectorbuilder.CustomActionManager, error) {
	l := ctxzap.Extract(ctx)

	actionManager := actions.NewActionManager(ctx)
	err := actionManager.RegisterAction(ctx, "disable_account", disableAccountActionSchema, c.disableAccountActionHandler)
	if err != nil {
		l.Error("failed to register action", zap.Error(err))
		return nil, err
	}

	return actionManager, nil
}

func (c *Connector) disableAccountActionHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	uidField, ok := args.Fields["resource_id"].GetKind().(*structpb.Value_StringValue)
	if !ok {
		return nil, nil, fmt.Errorf("missing resource ID")
	}

	uid := uidField.StringValue

	l := ctxzap.Extract(ctx)
	user, err := c.client.DisableUser(ctx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-tenable-vm: failed to disable user: %w", err)
	}

	if user != nil && user.Enabled {
		return nil, nil, fmt.Errorf("baton-tenable-vm: failed to disable user")
	}

	l.Info("baton-tenable-vm: user disabled successfully", zap.String("user_id", uid))

	responseStruct := structpb.Struct{
		Fields: map[string]*structpb.Value{
			"success": {
				Kind: &structpb.Value_BoolValue{BoolValue: true},
			},
		},
	}

	return &responseStruct, nil, err
}
