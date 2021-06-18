// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ScopeWithService scope with service
//
// swagger:model ScopeWithService
type ScopeWithService struct {

	// server id
	// Example: default
	AuthorizationServerID string `json:"authorization_server_id,omitempty"`

	// scope description which will be displayed as a hint on a consent page
	// Example: This scope value requests offline access using refresh token
	Description string `json:"description,omitempty"`

	// scope display name which will be displayed on a consent page
	// Example: Offline Access
	DisplayName string `json:"display_name,omitempty"`

	// scope id
	// Example: 1
	ID string `json:"id,omitempty"`

	// scope name
	// Example: offline_access
	Name string `json:"name,omitempty"`

	// service
	Service *Service `json:"service,omitempty"`

	// tenant id
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// with service
	WithService bool `json:"with_service,omitempty"`
}

// Validate validates this scope with service
func (m *ScopeWithService) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScopeWithService) validateService(formats strfmt.Registry) error {
	if swag.IsZero(m.Service) { // not required
		return nil
	}

	if m.Service != nil {
		if err := m.Service.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this scope with service based on the context it is used
func (m *ScopeWithService) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateService(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScopeWithService) contextValidateService(ctx context.Context, formats strfmt.Registry) error {

	if m.Service != nil {
		if err := m.Service.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ScopeWithService) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScopeWithService) UnmarshalBinary(b []byte) error {
	var res ScopeWithService
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
