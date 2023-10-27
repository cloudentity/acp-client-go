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

// WorkspaceRoleSubject workspace role subject
//
// swagger:model WorkspaceRoleSubject
type WorkspaceRoleSubject struct {

	// identity pool user pool id
	IdentityPoolID string `json:"identity_pool_id,omitempty"`

	// identity pool user id
	IdentityPoolUserID string `json:"identity_pool_user_id,omitempty"`

	// idp user idp id
	IdpID string `json:"idp_id,omitempty"`

	// roles
	Roles *WorkspaceRoles `json:"roles,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// type
	// Enum: [identity_pool_user idp]
	Type string `json:"type,omitempty"`

	// idp user workspace id
	WorkspaceID string `json:"workspace_id,omitempty"`
}

// Validate validates this workspace role subject
func (m *WorkspaceRoleSubject) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRoles(formats); err != nil {
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

func (m *WorkspaceRoleSubject) validateRoles(formats strfmt.Registry) error {
	if swag.IsZero(m.Roles) { // not required
		return nil
	}

	if m.Roles != nil {
		if err := m.Roles.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("roles")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("roles")
			}
			return err
		}
	}

	return nil
}

var workspaceRoleSubjectTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["identity_pool_user","idp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		workspaceRoleSubjectTypeTypePropEnum = append(workspaceRoleSubjectTypeTypePropEnum, v)
	}
}

const (

	// WorkspaceRoleSubjectTypeIdentityPoolUser captures enum value "identity_pool_user"
	WorkspaceRoleSubjectTypeIdentityPoolUser string = "identity_pool_user"

	// WorkspaceRoleSubjectTypeIdp captures enum value "idp"
	WorkspaceRoleSubjectTypeIdp string = "idp"
)

// prop value enum
func (m *WorkspaceRoleSubject) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, workspaceRoleSubjectTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WorkspaceRoleSubject) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this workspace role subject based on the context it is used
func (m *WorkspaceRoleSubject) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRoles(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WorkspaceRoleSubject) contextValidateRoles(ctx context.Context, formats strfmt.Registry) error {

	if m.Roles != nil {

		if swag.IsZero(m.Roles) { // not required
			return nil
		}

		if err := m.Roles.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("roles")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("roles")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *WorkspaceRoleSubject) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WorkspaceRoleSubject) UnmarshalBinary(b []byte) error {
	var res WorkspaceRoleSubject
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
