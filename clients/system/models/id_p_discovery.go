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

// IDPDiscovery ID p discovery
//
// swagger:model IDPDiscovery
type IDPDiscovery struct {

	// discovery mode
	// Enum: ["domain_matching","script_execution"]
	DiscoveryMode string `json:"discovery_mode,omitempty" yaml:"discovery_mode,omitempty"`

	// If enabled, IDP discovery automatically redirects the user to their own IDP and does not
	// display IDPs of other users while the users accesses the server/application.
	// Example: false
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

// Validate validates this ID p discovery
func (m *IDPDiscovery) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDiscoveryMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var idPDiscoveryTypeDiscoveryModePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["domain_matching","script_execution"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		idPDiscoveryTypeDiscoveryModePropEnum = append(idPDiscoveryTypeDiscoveryModePropEnum, v)
	}
}

const (

	// IDPDiscoveryDiscoveryModeDomainMatching captures enum value "domain_matching"
	IDPDiscoveryDiscoveryModeDomainMatching string = "domain_matching"

	// IDPDiscoveryDiscoveryModeScriptExecution captures enum value "script_execution"
	IDPDiscoveryDiscoveryModeScriptExecution string = "script_execution"
)

// prop value enum
func (m *IDPDiscovery) validateDiscoveryModeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, idPDiscoveryTypeDiscoveryModePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *IDPDiscovery) validateDiscoveryMode(formats strfmt.Registry) error {
	if swag.IsZero(m.DiscoveryMode) { // not required
		return nil
	}

	// value enum
	if err := m.validateDiscoveryModeEnum("discovery_mode", "body", m.DiscoveryMode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this ID p discovery based on context it is used
func (m *IDPDiscovery) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IDPDiscovery) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IDPDiscovery) UnmarshalBinary(b []byte) error {
	var res IDPDiscovery
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
