package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"
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
	// ConfigurationFields defines the external configuration required for the
	// connector to run. Note: these fields can be marked as optional or
	// required.
	ConfigurationFields = []field.SchemaField{SecretKeyField, AccessKeyField}
)

// ValidateConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func ValidateConfig(v *viper.Viper) error {
	return nil
}
