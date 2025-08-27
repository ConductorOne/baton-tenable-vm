package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	SecretKeyField = field.StringField(
		"secret-key",
		field.WithDescription("The Tenable API key connect to the Tenable API"),
		field.WithRequired(true),
	)
	AccessKeyField = field.StringField(
		"access-key",
		field.WithDescription("The Tenable API key connect to the Tenable API"),
		field.WithRequired(true),
	)
	EnableOnProvisionField = field.BoolField(
		"enable-on-provision",
		field.WithDescription("Enable user on provision if disabled"),
		field.WithDefaultValue(false),
	)
	// ConfigurationFields defines the external configuration required for the
	// connector to run. Note: these fields can be marked as optional or
	// required.
	ConfigurationFields = []field.SchemaField{SecretKeyField, AccessKeyField, EnableOnProvisionField}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	[]field.SchemaField{
		SecretKeyField,
		AccessKeyField,
		EnableOnProvisionField,
	},
	field.WithConnectorDisplayName("Tenable VM"),
	field.WithHelpUrl("/docs/baton/tenable-vm"),
	field.WithIconUrl("/static/app-icons/tenable-vm.svg"),
)
