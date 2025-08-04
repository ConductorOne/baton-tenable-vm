package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/conductorone/baton-tenable-vm/pkg/connector"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-tenable-vm",
		getConnector,
		field.Configuration{
			Fields: ConfigurationFields,
		},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	if err := ValidateConfig(v); err != nil {
		return nil, err
	}

	// PowerShellActions are defined in the config.
	// Get PowerShell actions from the StringMap field
	powershellActionsMap := make(map[string]connector.PowerShellAction)
	if v.IsSet("powershell-actions") {
		actionsMap := v.GetStringMap("powershell-actions")
		for name, actionData := range actionsMap {
			// Parse each action from the map
			if actionMap, ok := actionData.(map[string]interface{}); ok {
				action := connector.PowerShellAction{}

				// Get the path
				if path, ok := actionMap["path"].(string); ok {
					action.Path = path
				} else {
					return nil, fmt.Errorf("invalid powershell action configuration: missing path for action %s", name)
				}

				// Get the arguments
				action.Args = make(map[string]connector.PowerShellArgument)
				if argsData, ok := actionMap["args"].(map[string]interface{}); ok {
					for argName, argData := range argsData {
						if argMap, ok := argData.(map[string]interface{}); ok {
							arg := connector.PowerShellArgument{}

							if t, ok := argMap["type"].(string); ok {
								arg.Type = t
							}
							if dn, ok := argMap["display_name"].(string); ok {
								arg.DisplayName = dn
							}
							if desc, ok := argMap["description"].(string); ok {
								arg.Description = desc
							}
							if ph, ok := argMap["placeholder"].(string); ok {
								arg.Placeholder = ph
							}
							if req, ok := argMap["is_required"].(bool); ok {
								arg.IsRequired = req
							}
							if ops, ok := argMap["is_ops"].(bool); ok {
								arg.IsOps = ops
							}
							if secret, ok := argMap["is_secret"].(bool); ok {
								arg.IsSecret = secret
							}

							action.Args[argName] = arg
						}
					}
				}

				powershellActionsMap[name] = action
			}
		}
	}

	cb, err := connector.New(
		ctx,
		v.GetString(AccessKeyField.FieldName),
		v.GetString(SecretKeyField.FieldName),
		powershellActionsMap,
	)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	return connector, nil
}
