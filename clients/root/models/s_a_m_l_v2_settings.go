// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SAMLV2Settings s a m l v2 settings
//
// swagger:model SAMLV2Settings
type SAMLV2Settings struct {

	// IDP metadata URL
	MetadataURL string `json:"metadata_url,omitempty" yaml:"metadata_url,omitempty"`

	// IDP metadata xml
	MetadataXML string `json:"metadata_xml,omitempty" yaml:"metadata_xml,omitempty"`

	// SAML name id format.
	//
	// Format used in the NameIDPolicy for authentication requests
	// Example: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
	// Enum: [urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified urn:oasis:names:tc:SAML:2.0:nameid-format:transient urn:oasis:names:tc:SAML:2.0:nameid-format:persistent]
	NameIDFormat string `json:"name_id_format,omitempty" yaml:"name_id_format,omitempty"`

	// SAML signing method
	// Example: rsa-sha-256
	// Enum: [rsa-sha-256 rsa-sha-512 rsa-sha-1]
	SigningMethod string `json:"signing_method,omitempty" yaml:"signing_method,omitempty"`

	// SAML Assertion attribute that will be mapped to the Subject
	//
	// If empty than NameID will be used instead.
	UserIDAttribute string `json:"user_id_attribute,omitempty" yaml:"user_id_attribute,omitempty"`
}

// Validate validates this s a m l v2 settings
func (m *SAMLV2Settings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNameIDFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSigningMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var sAMLV2SettingsTypeNameIDFormatPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified","urn:oasis:names:tc:SAML:2.0:nameid-format:transient","urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		sAMLV2SettingsTypeNameIDFormatPropEnum = append(sAMLV2SettingsTypeNameIDFormatPropEnum, v)
	}
}

const (

	// SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML1Dot1NameidDashFormatEmailAddress captures enum value "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML1Dot1NameidDashFormatEmailAddress string = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	// SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML1Dot1NameidDashFormatUnspecified captures enum value "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML1Dot1NameidDashFormatUnspecified string = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	// SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML2Dot0NameidDashFormatTransient captures enum value "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML2Dot0NameidDashFormatTransient string = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	// SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML2Dot0NameidDashFormatPersistent captures enum value "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	SAMLV2SettingsNameIDFormatUrnOasisNamesTcSAML2Dot0NameidDashFormatPersistent string = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// prop value enum
func (m *SAMLV2Settings) validateNameIDFormatEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, sAMLV2SettingsTypeNameIDFormatPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SAMLV2Settings) validateNameIDFormat(formats strfmt.Registry) error {
	if swag.IsZero(m.NameIDFormat) { // not required
		return nil
	}

	// value enum
	if err := m.validateNameIDFormatEnum("name_id_format", "body", m.NameIDFormat); err != nil {
		return err
	}

	return nil
}

var sAMLV2SettingsTypeSigningMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["rsa-sha-256","rsa-sha-512","rsa-sha-1"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		sAMLV2SettingsTypeSigningMethodPropEnum = append(sAMLV2SettingsTypeSigningMethodPropEnum, v)
	}
}

const (

	// SAMLV2SettingsSigningMethodRsaDashShaDash256 captures enum value "rsa-sha-256"
	SAMLV2SettingsSigningMethodRsaDashShaDash256 string = "rsa-sha-256"

	// SAMLV2SettingsSigningMethodRsaDashShaDash512 captures enum value "rsa-sha-512"
	SAMLV2SettingsSigningMethodRsaDashShaDash512 string = "rsa-sha-512"

	// SAMLV2SettingsSigningMethodRsaDashShaDash1 captures enum value "rsa-sha-1"
	SAMLV2SettingsSigningMethodRsaDashShaDash1 string = "rsa-sha-1"
)

// prop value enum
func (m *SAMLV2Settings) validateSigningMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, sAMLV2SettingsTypeSigningMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SAMLV2Settings) validateSigningMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.SigningMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateSigningMethodEnum("signing_method", "body", m.SigningMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this s a m l v2 settings based on context it is used
func (m *SAMLV2Settings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLV2Settings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLV2Settings) UnmarshalBinary(b []byte) error {
	var res SAMLV2Settings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
