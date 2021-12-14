// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ServiceWithScopesAndAPIs service with scopes and a p is
//
// swagger:model ServiceWithScopesAndAPIs
type ServiceWithScopesAndAPIs struct {

	// list of apis
	Apis []*API `json:"apis"`

	// server id
	// Example: default
	AuthorizationServerID string `json:"authorization_server_id,omitempty"`

	// custom service audience
	// Example: https://api.example.com
	CustomAudience string `json:"custom_audience,omitempty"`

	// service description
	// Example: Service description
	Description string `json:"description,omitempty"`

	// gateway id
	GatewayID string `json:"gateway_id,omitempty"`

	// unique service id
	// Example: 1
	ID string `json:"id,omitempty"`

	// service name
	// Example: Sample service
	Name string `json:"name,omitempty"`

	// list of scopes
	Scopes []*Scope `json:"scopes"`

	// Is service a system service
	// Example: false
	System bool `json:"system,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// true if service has openapi 3 specification
	WithSpecification bool `json:"with_specification,omitempty"`
}

// Validate validates this service with scopes and a p is
func (m *ServiceWithScopesAndAPIs) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScopes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServiceWithScopesAndAPIs) validateApis(formats strfmt.Registry) error {
	if swag.IsZero(m.Apis) { // not required
		return nil
	}

	for i := 0; i < len(m.Apis); i++ {
		if swag.IsZero(m.Apis[i]) { // not required
			continue
		}

		if m.Apis[i] != nil {
			if err := m.Apis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServiceWithScopesAndAPIs) validateScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.Scopes) { // not required
		return nil
	}

	for i := 0; i < len(m.Scopes); i++ {
		if swag.IsZero(m.Scopes[i]) { // not required
			continue
		}

		if m.Scopes[i] != nil {
			if err := m.Scopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this service with scopes and a p is based on the context it is used
func (m *ServiceWithScopesAndAPIs) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ServiceWithScopesAndAPIs) contextValidateApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Apis); i++ {

		if m.Apis[i] != nil {
			if err := m.Apis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ServiceWithScopesAndAPIs) contextValidateScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Scopes); i++ {

		if m.Scopes[i] != nil {
			if err := m.Scopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ServiceWithScopesAndAPIs) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ServiceWithScopesAndAPIs) UnmarshalBinary(b []byte) error {
	var res ServiceWithScopesAndAPIs
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}