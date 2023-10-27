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

// IdentityPoolRoleSubject identity pool role subject
//
// swagger:model IdentityPoolRoleSubject
type IdentityPoolRoleSubject struct {

	// identity pool user pool id
	IdentityPoolID string `json:"identity_pool_id,omitempty"`

	// identity pool user id
	IdentityPoolUserID string `json:"identity_pool_user_id,omitempty"`

	// idp user idp id
	IdpID string `json:"idp_id,omitempty"`

	// roles
	Roles *IdentityPoolRoles `json:"roles,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// type
	// Enum: [identity_pool_user idp]
	Type string `json:"type,omitempty"`

	// idp user workspace id
	WorkspaceID string `json:"workspace_id,omitempty"`
}

// Validate validates this identity pool role subject
func (m *IdentityPoolRoleSubject) Validate(formats strfmt.Registry) error {
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

func (m *IdentityPoolRoleSubject) validateRoles(formats strfmt.Registry) error {
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

var identityPoolRoleSubjectTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["identity_pool_user","idp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		identityPoolRoleSubjectTypeTypePropEnum = append(identityPoolRoleSubjectTypeTypePropEnum, v)
	}
}

const (

	// IdentityPoolRoleSubjectTypeIdentityPoolUser captures enum value "identity_pool_user"
	IdentityPoolRoleSubjectTypeIdentityPoolUser string = "identity_pool_user"

	// IdentityPoolRoleSubjectTypeIdp captures enum value "idp"
	IdentityPoolRoleSubjectTypeIdp string = "idp"
)

// prop value enum
func (m *IdentityPoolRoleSubject) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, identityPoolRoleSubjectTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *IdentityPoolRoleSubject) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this identity pool role subject based on the context it is used
func (m *IdentityPoolRoleSubject) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRoles(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityPoolRoleSubject) contextValidateRoles(ctx context.Context, formats strfmt.Registry) error {

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
func (m *IdentityPoolRoleSubject) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityPoolRoleSubject) UnmarshalBinary(b []byte) error {
	var res IdentityPoolRoleSubject
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
