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

// GrantTenantRoleRequest grant tenant role request
//
// swagger:model GrantTenantRoleRequest
type GrantTenantRoleRequest struct {

	// identity pool user pool id
	IdentityPoolID string `json:"identity_pool_id,omitempty" yaml:"identity_pool_id,omitempty"`

	// identity pool user id
	IdentityPoolUserID string `json:"identity_pool_user_id,omitempty" yaml:"identity_pool_user_id,omitempty"`

	// idp user idp id
	IdpID string `json:"idp_id,omitempty" yaml:"idp_id,omitempty"`

	// role
	// Example: admin
	// Enum: [admin business_admin auditor member]
	Role string `json:"role,omitempty" yaml:"role,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// type
	// Enum: [identity_pool_user idp]
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	// idp user workspace id
	WorkspaceID string `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`
}

// Validate validates this grant tenant role request
func (m *GrantTenantRoleRequest) Validate(formats strfmt.Registry) error {
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

var grantTenantRoleRequestTypeRolePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["admin","business_admin","auditor","member"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		grantTenantRoleRequestTypeRolePropEnum = append(grantTenantRoleRequestTypeRolePropEnum, v)
	}
}

const (

	// GrantTenantRoleRequestRoleAdmin captures enum value "admin"
	GrantTenantRoleRequestRoleAdmin string = "admin"

	// GrantTenantRoleRequestRoleBusinessAdmin captures enum value "business_admin"
	GrantTenantRoleRequestRoleBusinessAdmin string = "business_admin"

	// GrantTenantRoleRequestRoleAuditor captures enum value "auditor"
	GrantTenantRoleRequestRoleAuditor string = "auditor"

	// GrantTenantRoleRequestRoleMember captures enum value "member"
	GrantTenantRoleRequestRoleMember string = "member"
)

// prop value enum
func (m *GrantTenantRoleRequest) validateRoleEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, grantTenantRoleRequestTypeRolePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GrantTenantRoleRequest) validateRole(formats strfmt.Registry) error {
	if swag.IsZero(m.Role) { // not required
		return nil
	}

	// value enum
	if err := m.validateRoleEnum("role", "body", m.Role); err != nil {
		return err
	}

	return nil
}

var grantTenantRoleRequestTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["identity_pool_user","idp"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		grantTenantRoleRequestTypeTypePropEnum = append(grantTenantRoleRequestTypeTypePropEnum, v)
	}
}

const (

	// GrantTenantRoleRequestTypeIdentityPoolUser captures enum value "identity_pool_user"
	GrantTenantRoleRequestTypeIdentityPoolUser string = "identity_pool_user"

	// GrantTenantRoleRequestTypeIdp captures enum value "idp"
	GrantTenantRoleRequestTypeIdp string = "idp"
)

// prop value enum
func (m *GrantTenantRoleRequest) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, grantTenantRoleRequestTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GrantTenantRoleRequest) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this grant tenant role request based on context it is used
func (m *GrantTenantRoleRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GrantTenantRoleRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GrantTenantRoleRequest) UnmarshalBinary(b []byte) error {
	var res GrantTenantRoleRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
