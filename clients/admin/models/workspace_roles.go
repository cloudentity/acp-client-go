// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// WorkspaceRoles workspace roles
//
// swagger:model WorkspaceRoles
type WorkspaceRoles struct {

	// admin
	Admin bool `json:"admin,omitempty" yaml:"admin,omitempty"`

	// auditor
	Auditor bool `json:"auditor,omitempty" yaml:"auditor,omitempty"`

	// manager
	Manager bool `json:"manager,omitempty" yaml:"manager,omitempty"`

	// member
	Member bool `json:"member,omitempty" yaml:"member,omitempty"`

	// user manager
	UserManager bool `json:"user_manager,omitempty" yaml:"user_manager,omitempty"`
}

// Validate validates this workspace roles
func (m *WorkspaceRoles) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this workspace roles based on context it is used
func (m *WorkspaceRoles) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *WorkspaceRoles) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WorkspaceRoles) UnmarshalBinary(b []byte) error {
	var res WorkspaceRoles
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
