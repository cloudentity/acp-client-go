// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AuthorizationDetailWithService authorization detail with service
//
// swagger:model AuthorizationDetailWithService
type AuthorizationDetailWithService struct {

	// An authorization server (workspace) identifier holding the client application.
	// Example: default
	// Required: true
	AuthorizationServerID string `json:"authorization_server_id" yaml:"authorization_server_id"`

	// Description
	// Example: Authorization detail for payment initiation
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Authorization detail unique identifier
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// General purpose metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Display name
	// Example: Payment Initiation
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// schema
	Schema *SupportedJSONSchema `json:"schema,omitempty" yaml:"schema,omitempty"`

	// service
	Service *Service `json:"service,omitempty" yaml:"service,omitempty"`

	// ID of the tenant
	// Example: default
	// Required: true
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// type
	// Required: true
	Type *AuthorizationDetailType `json:"type" yaml:"type"`
}

// Validate validates this authorization detail with service
func (m *AuthorizationDetailWithService) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorizationServerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchema(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthorizationDetailWithService) validateAuthorizationServerID(formats strfmt.Registry) error {

	if err := validate.RequiredString("authorization_server_id", "body", m.AuthorizationServerID); err != nil {
		return err
	}

	return nil
}

func (m *AuthorizationDetailWithService) validateSchema(formats strfmt.Registry) error {
	if swag.IsZero(m.Schema) { // not required
		return nil
	}

	if m.Schema != nil {
		if err := m.Schema.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("schema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("schema")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationDetailWithService) validateService(formats strfmt.Registry) error {
	if swag.IsZero(m.Service) { // not required
		return nil
	}

	if m.Service != nil {
		if err := m.Service.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationDetailWithService) validateTenantID(formats strfmt.Registry) error {

	if err := validate.RequiredString("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

func (m *AuthorizationDetailWithService) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if m.Type != nil {
		if err := m.Type.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this authorization detail with service based on the context it is used
func (m *AuthorizationDetailWithService) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSchema(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateService(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthorizationDetailWithService) contextValidateSchema(ctx context.Context, formats strfmt.Registry) error {

	if m.Schema != nil {

		if swag.IsZero(m.Schema) { // not required
			return nil
		}

		if err := m.Schema.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("schema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("schema")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationDetailWithService) contextValidateService(ctx context.Context, formats strfmt.Registry) error {

	if m.Service != nil {

		if swag.IsZero(m.Service) { // not required
			return nil
		}

		if err := m.Service.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationDetailWithService) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if m.Type != nil {

		if err := m.Type.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuthorizationDetailWithService) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthorizationDetailWithService) UnmarshalBinary(b []byte) error {
	var res AuthorizationDetailWithService
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
