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

// Role role
//
// swagger:model Role
type Role struct {

	// resource
	Resource *RoleResource `json:"resource,omitempty" yaml:"resource,omitempty"`

	// role
	// Enum: [admin business_admin auditor manager user_manager member]
	Role string `json:"role,omitempty" yaml:"role,omitempty"`

	// subject
	Subject *RoleSubject `json:"subject,omitempty" yaml:"subject,omitempty"`
}

// Validate validates this role
func (m *Role) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateResource(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRole(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubject(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Role) validateResource(formats strfmt.Registry) error {
	if swag.IsZero(m.Resource) { // not required
		return nil
	}

	if m.Resource != nil {
		if err := m.Resource.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("resource")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("resource")
			}
			return err
		}
	}

	return nil
}

var roleTypeRolePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["admin","business_admin","auditor","manager","user_manager","member"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		roleTypeRolePropEnum = append(roleTypeRolePropEnum, v)
	}
}

const (

	// RoleRoleAdmin captures enum value "admin"
	RoleRoleAdmin string = "admin"

	// RoleRoleBusinessAdmin captures enum value "business_admin"
	RoleRoleBusinessAdmin string = "business_admin"

	// RoleRoleAuditor captures enum value "auditor"
	RoleRoleAuditor string = "auditor"

	// RoleRoleManager captures enum value "manager"
	RoleRoleManager string = "manager"

	// RoleRoleUserManager captures enum value "user_manager"
	RoleRoleUserManager string = "user_manager"

	// RoleRoleMember captures enum value "member"
	RoleRoleMember string = "member"
)

// prop value enum
func (m *Role) validateRoleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, roleTypeRolePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Role) validateRole(formats strfmt.Registry) error {
	if swag.IsZero(m.Role) { // not required
		return nil
	}

	// value enum
	if err := m.validateRoleEnum("role", "body", m.Role); err != nil {
		return err
	}

	return nil
}

func (m *Role) validateSubject(formats strfmt.Registry) error {
	if swag.IsZero(m.Subject) { // not required
		return nil
	}

	if m.Subject != nil {
		if err := m.Subject.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("subject")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("subject")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this role based on the context it is used
func (m *Role) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateResource(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubject(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Role) contextValidateResource(ctx context.Context, formats strfmt.Registry) error {

	if m.Resource != nil {

		if swag.IsZero(m.Resource) { // not required
			return nil
		}

		if err := m.Resource.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("resource")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("resource")
			}
			return err
		}
	}

	return nil
}

func (m *Role) contextValidateSubject(ctx context.Context, formats strfmt.Registry) error {

	if m.Subject != nil {

		if swag.IsZero(m.Subject) { // not required
			return nil
		}

		if err := m.Subject.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("subject")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("subject")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Role) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Role) UnmarshalBinary(b []byte) error {
	var res Role
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
