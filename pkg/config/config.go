package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	SecretKeyField = field.StringField(
		"secret-key",
		field.WithDescription("Tenable VM secret key to connect to the API"),
		field.WithDisplayName("Secret Key"),
		field.WithPlaceholder("Your Tenable VM Secret Key"),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	AccessKeyField = field.StringField(
		"access-key",
		field.WithDescription("Tenable VM access key to connect to the API"),
		field.WithDisplayName("Access Key"),
		field.WithPlaceholder("Your Tenable VM Access Key"),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	BaseURLField = field.StringField(
		"base-url",
		field.WithDisplayName("Base URL"),
		field.WithDescription("Tenable Vulnerability Management API base URL. Defaults to the commercial cloud; use https://fedcloud.tenable.com for FedRAMP Moderate."),
		// Keep in sync with client.BaseURL (commercial cloud host from main).
		field.WithDefaultValue("https://cloud.tenable.com"),
	)
	EnableOnProvisionField = field.BoolField(
		"enable-on-provision",
		field.WithDescription("Enable user on provision if disabled"),
		field.WithDefaultValue(false),
		field.WithDisplayName("Enable user on provisioning"),
	)
	// ConfigurationFields defines the external configuration required for the
	// connector to run. Note: these fields can be marked as optional or
	// required.
	ConfigurationFields = []field.SchemaField{SecretKeyField, AccessKeyField, BaseURLField, EnableOnProvisionField}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("Tenable VM"),
	field.WithHelpUrl("/docs/baton/tenable-vm"),
	field.WithIconUrl("/static/app-icons/tenable-vm.svg"),
)
