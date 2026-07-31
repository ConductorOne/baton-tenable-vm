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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ActionDisableAccount = "disable_account"
	ActionEnableAccount  = "enable_account"
)

var disableAccountActionSchema = &v2.BatonActionSchema{
	Name:        ActionDisableAccount,
	DisplayName: "Disable Account",
	Description: "Disables a user account",
	Arguments: []*config.Field{
		{
			Name:        fieldUserID,
			DisplayName: "User Resource ID",
			Description: "The ID of the user to disable",
			Field:       &config.Field_IntField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        fieldSuccess,
			DisplayName: "Success",
			Description: "Whether the account was disabled successfully",
			Field:       &config.Field_BoolField{},
		},
	},
}

var enableAccountActionSchema = &v2.BatonActionSchema{
	Name:        ActionEnableAccount,
	DisplayName: "Enable Account",
	Description: "Enables a user account",
	Arguments: []*config.Field{
		{
			Name:        fieldUserID,
			DisplayName: "User Resource ID",
			Description: "The ID of the user to enable",
			Field:       &config.Field_IntField{},
			IsRequired:  true,
		},
	},
	ReturnTypes: []*config.Field{
		{
			Name:        fieldSuccess,
			DisplayName: "Success",
			Description: "Whether the account was enabled successfully",
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

	err = actionManager.RegisterAction(ctx, "enable_account", enableAccountActionSchema, c.enableAccountActionHandler)
	if err != nil {
		l.Error("failed to register action", zap.Error(err))
		return nil, err
	}

	return actionManager, nil
}

func (c *Connector) disableAccountActionHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if args == nil || args.Fields == nil {
		l.Error("baton-tenable-vm: disable action error invalid arguments")
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid arguments")
	}

	resourceIDValue, exists := args.Fields[fieldUserID]
	if !exists || resourceIDValue == nil {
		l.Error("baton-tenable-vm: disable action error missing user ID")
		return nil, nil, status.Errorf(codes.InvalidArgument, "missing user id")
	}

	uid, err := extractActionUserID(resourceIDValue)
	if err != nil {
		l.Error("baton-tenable-vm: disable action error invalid user ID format", zap.Error(err))
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid user ID format")
	}

	user, err := c.client.DisableUser(ctx, uid)
	if err != nil {
		l.Error("baton-tenable-vm: disable action error failed to disable user", zap.Error(err))
		wrappedErr := fmt.Errorf("baton-tenable-vm: failed to disable user: %w", err)
		return nil, nil, status.Error(codes.Internal, wrappedErr.Error())
	}

	if user != nil && user.Enabled {
		l.Error("baton-tenable-vm: disable action error user is still enabled", zap.String(fieldUserID, uid))
		return nil, nil, status.Errorf(codes.FailedPrecondition, "baton-tenable-vm: disable user returned success but user %s is still enabled", uid)
	}

	l.Info("baton-tenable-vm: user disabled successfully", zap.String(fieldUserID, uid))

	return getResponseStruct(true), nil, err
}

func (c *Connector) enableAccountActionHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if args == nil || args.Fields == nil {
		l.Error("baton-tenable-vm: enable action error invalid arguments")
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid arguments")
	}

	resourceIDValue, exists := args.Fields[fieldUserID]
	if !exists || resourceIDValue == nil {
		l.Error("baton-tenable-vm: enable action error missing user ID")
		return nil, nil, status.Errorf(codes.InvalidArgument, "missing user ID")
	}

	uid, err := extractActionUserID(resourceIDValue)
	if err != nil {
		l.Error("baton-tenable-vm: enable action error invalid user ID format", zap.Error(err))
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid user ID format")
	}

	user, err := c.client.EnableUser(ctx, uid)
	if err != nil {
		l.Error("baton-tenable-vm: enable action error failed to enable user", zap.Error(err))
		wrappedErr := fmt.Errorf("baton-tenable-vm: failed to enable user: %w", err)
		return nil, nil, status.Error(codes.Internal, wrappedErr.Error())
	}

	if user != nil && !user.Enabled {
		l.Error("baton-tenable-vm: enable action error user is still disabled", zap.String(fieldUserID, uid))
		return nil, nil, status.Errorf(codes.FailedPrecondition, "baton-tenable-vm: enable user returned success but user %s is still disabled", uid)
	}

	l.Info("baton-tenable-vm: user enabled successfully", zap.String(fieldUserID, uid))

	return getResponseStruct(true), nil, err
}

func getResponseStruct(success bool) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			fieldSuccess: {
				Kind: &structpb.Value_BoolValue{BoolValue: success},
			},
		},
	}
}
