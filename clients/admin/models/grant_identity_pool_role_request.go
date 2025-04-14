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

// GrantIdentityPoolRoleRequest grant identity pool role request
//
// swagger:model GrantIdentityPoolRoleRequest
type GrantIdentityPoolRoleRequest struct {

	// identity pool user pool id
	IdentityPoolID string `json:"identity_pool_id,omitempty" yaml:"identity_pool_id,omitempty"`

	// identity pool user id
	IdentityPoolUserID string `json:"identity_pool_user_id,omitempty" yaml:"identity_pool_user_id,omitempty"`

	// idp user idp id
	IdpID string `json:"idp_id,omitempty" yaml:"idp_id,omitempty"`

	// role
	// Example: user_manager
	// Enum: [user_manager]
	Role string `json:"role,omitempty" yaml:"role,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// type
	// Enum: [identity_pool_user idp]
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	// idp user workspace id
	WorkspaceID string `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`
}

// Validate validates this grant identity pool role request
func (m *GrantIdentityPoolRoleRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRole(formats); err != nil {
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

var grantIdentityPoolRoleRequestTypeRolePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["user_manager"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		grantIdentityPoolRoleRequestTypeRolePropEnum = append(grantIdentityPoolRoleRequestTypeRolePropEnum, v)
	}
}

const (

	// GrantIdentityPoolRoleRequestRoleUserManager captures enum value "user_manager"
	GrantIdentityPoolRoleRequestRoleUserManager string = "user_manager"
)

// prop value enum
func (m *GrantIdentityPoolRoleRequest) validateRoleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, grantIdentityPoolRoleRequestTypeRolePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GrantIdentityPoolRoleRequest) validateRole(formats strfmt.Registry) error {
	if swag.IsZero(m.Role) { // not required
		return nil
	}

	// value enum
	if err := m.validateRoleEnum("role", "body", m.Role); err != nil {
		return err
	}

	return nil
}

var grantIdentityPoolRoleRequestTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["identity_pool_user","idp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		grantIdentityPoolRoleRequestTypeTypePropEnum = append(grantIdentityPoolRoleRequestTypeTypePropEnum, v)
	}
}

const (

	// GrantIdentityPoolRoleRequestTypeIdentityPoolUser captures enum value "identity_pool_user"
	GrantIdentityPoolRoleRequestTypeIdentityPoolUser string = "identity_pool_user"

	// GrantIdentityPoolRoleRequestTypeIdp captures enum value "idp"
	GrantIdentityPoolRoleRequestTypeIdp string = "idp"
)

// prop value enum
func (m *GrantIdentityPoolRoleRequest) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, grantIdentityPoolRoleRequestTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GrantIdentityPoolRoleRequest) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this grant identity pool role request based on context it is used
func (m *GrantIdentityPoolRoleRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GrantIdentityPoolRoleRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GrantIdentityPoolRoleRequest) UnmarshalBinary(b []byte) error {
	var res GrantIdentityPoolRoleRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
