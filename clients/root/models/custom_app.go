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

// CustomApp Custom Branding CustomApp
//
// swagger:model CustomApp
type CustomApp struct {

	// ClientID used for the CustomApp
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// ID of the CustomApp
	// Required: true
	ID string `json:"id" yaml:"id"`

	// Name of the CustomApp
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// ID of the server
	// Required: true
	ServerID string `json:"server_id" yaml:"server_id"`

	// ID of the tenant
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// Type of the custom app
	// Example: post-authn
	// Enum: [post-authn]
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	// url of the CustomApp
	// Required: true
	URL string `json:"url" yaml:"url"`
}

// Validate validates this custom app
func (m *CustomApp) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateURL(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CustomApp) validateID(formats strfmt.Registry) error {

	if err := validate.RequiredString("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *CustomApp) validateServerID(formats strfmt.Registry) error {

	if err := validate.RequiredString("server_id", "body", m.ServerID); err != nil {
		return err
	}

	return nil
}

func (m *CustomApp) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

var customAppTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["post-authn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		customAppTypeTypePropEnum = append(customAppTypeTypePropEnum, v)
	}
}

const (

	// CustomAppTypePostDashAuthn captures enum value "post-authn"
	CustomAppTypePostDashAuthn string = "post-authn"
)

// prop value enum
func (m *CustomApp) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, customAppTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CustomApp) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *CustomApp) validateURL(formats strfmt.Registry) error {

	if err := validate.RequiredString("url", "body", m.URL); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this custom app based on context it is used
func (m *CustomApp) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CustomApp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CustomApp) UnmarshalBinary(b []byte) error {
	var res CustomApp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
