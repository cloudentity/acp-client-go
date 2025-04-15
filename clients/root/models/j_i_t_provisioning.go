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

// JITProvisioning j i t provisioning
//
// swagger:model JITProvisioning
type JITProvisioning struct {

	// Admin role assigned to the provisioned user if JIT is enabled (available only for admin workspaces only)
	// Enum: ["admin","business_admin","auditor","member"]
	AdminRoleType string `json:"admin_role_type,omitempty" yaml:"admin_role_type,omitempty"`

	// identifier salt
	IdentifierSalt string `json:"identifier_salt,omitempty" yaml:"identifier_salt,omitempty"`

	// mode
	Mode ProvisioningMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// pool id
	PoolID string `json:"pool_id,omitempty" yaml:"pool_id,omitempty"`

	// pre provisioning
	PreProvisioning *PreProvisioningConfiguration `json:"pre_provisioning,omitempty" yaml:"pre_provisioning,omitempty"`

	// user
	User *JITUser `json:"user,omitempty" yaml:"user,omitempty"`
}

// Validate validates this j i t provisioning
func (m *JITProvisioning) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAdminRoleType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePreProvisioning(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUser(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var jITProvisioningTypeAdminRoleTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["admin","business_admin","auditor","member"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		jITProvisioningTypeAdminRoleTypePropEnum = append(jITProvisioningTypeAdminRoleTypePropEnum, v)
	}
}

const (

	// JITProvisioningAdminRoleTypeAdmin captures enum value "admin"
	JITProvisioningAdminRoleTypeAdmin string = "admin"

	// JITProvisioningAdminRoleTypeBusinessAdmin captures enum value "business_admin"
	JITProvisioningAdminRoleTypeBusinessAdmin string = "business_admin"

	// JITProvisioningAdminRoleTypeAuditor captures enum value "auditor"
	JITProvisioningAdminRoleTypeAuditor string = "auditor"

	// JITProvisioningAdminRoleTypeMember captures enum value "member"
	JITProvisioningAdminRoleTypeMember string = "member"
)

// prop value enum
func (m *JITProvisioning) validateAdminRoleTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, jITProvisioningTypeAdminRoleTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *JITProvisioning) validateAdminRoleType(formats strfmt.Registry) error {
	if swag.IsZero(m.AdminRoleType) { // not required
		return nil
	}

	// value enum
	if err := m.validateAdminRoleTypeEnum("admin_role_type", "body", m.AdminRoleType); err != nil {
		return err
	}

	return nil
}

func (m *JITProvisioning) validateMode(formats strfmt.Registry) error {
	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

func (m *JITProvisioning) validatePreProvisioning(formats strfmt.Registry) error {
	if swag.IsZero(m.PreProvisioning) { // not required
		return nil
	}

	if m.PreProvisioning != nil {
		if err := m.PreProvisioning.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pre_provisioning")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pre_provisioning")
			}
			return err
		}
	}

	return nil
}

func (m *JITProvisioning) validateUser(formats strfmt.Registry) error {
	if swag.IsZero(m.User) { // not required
		return nil
	}

	if m.User != nil {
		if err := m.User.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("user")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("user")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this j i t provisioning based on the context it is used
func (m *JITProvisioning) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePreProvisioning(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUser(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JITProvisioning) contextValidateMode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Mode) { // not required
		return nil
	}

	if err := m.Mode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("mode")
		}
		return err
	}

	return nil
}

func (m *JITProvisioning) contextValidatePreProvisioning(ctx context.Context, formats strfmt.Registry) error {

	if m.PreProvisioning != nil {

		if swag.IsZero(m.PreProvisioning) { // not required
			return nil
		}

		if err := m.PreProvisioning.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pre_provisioning")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pre_provisioning")
			}
			return err
		}
	}

	return nil
}

func (m *JITProvisioning) contextValidateUser(ctx context.Context, formats strfmt.Registry) error {

	if m.User != nil {

		if swag.IsZero(m.User) { // not required
			return nil
		}

		if err := m.User.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("user")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("user")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *JITProvisioning) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JITProvisioning) UnmarshalBinary(b []byte) error {
	var res JITProvisioning
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
