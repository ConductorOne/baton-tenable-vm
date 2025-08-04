package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

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

	// Register each PowerShell action from the configuration as a separate action
	for actionName, psAction := range c.PowerShellActions {
		psSchema, err := createPowerShellActionSchemaForAction(actionName, psAction)
		if err != nil {
			l.Error("failed to create PowerShell action schema", zap.Error(err))
			return nil, err
		}

		l.Debug("registering action", zap.String("actionName", actionName), zap.Any("psSchema", psSchema))
		err = actionManager.RegisterAction(ctx, actionName, psSchema, func(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
			return c.executePowershellAction(ctx, actionName, args)
		})
		if err != nil {
			l.Error("failed to register action", zap.Error(err))
			return nil, err
		}
	}

	return actionManager, nil
}

// createPowerShellActionSchemaForAction creates a BatonActionSchema for a specific PowerShell action.
func createPowerShellActionSchemaForAction(actionName string, action PowerShellAction) (*v2.BatonActionSchema, error) {
	schema := &v2.BatonActionSchema{
		Name:        actionName,
		DisplayName: fmt.Sprintf("PowerShell: %s", actionName),
		Description: fmt.Sprintf("Executes the PowerShell script: %s", action.Path),
		Arguments:   []*config.Field{},
		ReturnTypes: []*config.Field{
			{
				Name:        "success",
				DisplayName: "Success",
				Description: "Whether the command was executed successfully",
				Field:       &config.Field_BoolField{},
			},
			{
				Name:        "stdout",
				DisplayName: "Standard Output",
				Description: "The standard output from the command",
				Field:       &config.Field_StringField{},
			},
			{
				Name:        "stderr",
				DisplayName: "Standard Error",
				Description: "The standard error from the command",
				Field:       &config.Field_StringField{},
			},
			{
				Name:        "exit_code",
				DisplayName: "Exit Code",
				Description: "The exit code returned by the command (numeric value)",
				Field:       &config.Field_IntField{},
			},
		},
	}

	// Add each configured argument as a field in the schema
	for argName, argInfo := range action.Args {
		field := &config.Field{
			Name:        argName,
			DisplayName: argInfo.DisplayName,
			Description: argInfo.Description,
			IsRequired:  argInfo.IsRequired,
			Placeholder: argInfo.Placeholder,
			IsOps:       argInfo.IsOps,
			IsSecret:    argInfo.IsSecret,
		}

		switch argInfo.Type {
		case "int":
			field.Field = &config.Field_IntField{}
		case "bool":
			field.Field = &config.Field_BoolField{}
		case "string":
			field.Field = &config.Field_StringField{}
		default:
			return nil, fmt.Errorf("unsupported argument type: %s", argInfo.Type)
		}

		schema.Arguments = append(schema.Arguments, field)
	}

	return schema, nil
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

func (c *Connector) executePowershellAction(ctx context.Context, actionName string, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Find the corresponding action configuration
	psAction, ok := c.PowerShellActions[actionName]
	if !ok {
		l.Error("baton-active-directory: execute-powershell-action: PowerShell action not found in configuration", zap.String("action", actionName))
		return nil, nil, fmt.Errorf("PowerShell action not found in configuration: %s", actionName)
	}

	// Build command arguments based on the configured action
	cmdArgs := []string{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", psAction.Path,
	}

	// Process action arguments from the request
	for argName, argInfo := range psAction.Args {
		// Check if the argument is provided in the request
		argField, ok := args.Fields[argName]
		if !ok {
			if argInfo.IsRequired {
				l.Error("baton-active-directory: execute-powershell-action: missing required argument",
					zap.String("action", actionName),
					zap.String("argument", argName))

				return nil, nil, fmt.Errorf("missing required argument: %s", argName)
			}
			continue
		}

		// Extract the value based on the expected type defined in config
		var argValue string
		typeOk := false

		switch argInfo.Type {
		case "string":
			if strVal, ok := argField.GetKind().(*structpb.Value_StringValue); ok {
				argValue = strVal.StringValue
				typeOk = true
			}
		case "int":
			if numVal, ok := argField.GetKind().(*structpb.Value_NumberValue); ok {
				argValue = fmt.Sprintf("%d", int(numVal.NumberValue))
				typeOk = true
			}
		case "bool":
			if boolVal, ok := argField.GetKind().(*structpb.Value_BoolValue); ok {
				argValue = fmt.Sprintf("%v", boolVal.BoolValue)
				typeOk = true
			}
		}

		if !typeOk {
			l.Error("baton-active-directory: execute-powershell-action: type mismatch for argument",
				zap.String("action", actionName),
				zap.String("argument", argName),
				zap.String("expected_type", argInfo.Type))
			return nil, nil, fmt.Errorf("type mismatch for argument: %s", argName)
		}

		// Add the argument to the command
		cmdArgs = append(cmdArgs, fmt.Sprintf("-%s", argName), argValue)
	}

	// Create a command to execute PowerShell script
	cmd := exec.CommandContext(ctx, "powershell.exe", cmdArgs...)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	err := cmd.Run()

	// Extract exit code
	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	}

	// Prepare response with command output
	result := structpb.Struct{
		Fields: map[string]*structpb.Value{
			"success": {
				Kind: &structpb.Value_BoolValue{BoolValue: err == nil},
			},
			"stdout": {
				Kind: &structpb.Value_StringValue{StringValue: stdout.String()},
			},
			"stderr": {
				Kind: &structpb.Value_StringValue{StringValue: stderr.String()},
			},
			"exit_code": {
				Kind: &structpb.Value_NumberValue{NumberValue: float64(exitCode)},
			},
		},
	}

	if err != nil {
		l.Error("baton-active-directory: execute-powershell-action: failed to execute script",
			zap.Error(err),
			zap.String("action", actionName),
			zap.String("path", psAction.Path),
			zap.Int("exit_code", exitCode))

		// Still return the result with error output
		return &result, nil, nil
	}

	l.Info("baton-active-directory: execute-powershell-action: successfully executed script",
		zap.String("action", actionName),
		zap.String("path", psAction.Path))
	return &result, nil, nil
}
