// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PoolPermissionsResponse pool permissions response
//
// swagger:model PoolPermissionsResponse
type PoolPermissionsResponse struct {

	// b2b manage admin metadata
	B2bManageAdminMetadata bool `json:"b2b_manage_admin_metadata,omitempty" yaml:"b2b_manage_admin_metadata,omitempty"`

	// b2b manage business metadata
	B2bManageBusinessMetadata bool `json:"b2b_manage_business_metadata,omitempty" yaml:"b2b_manage_business_metadata,omitempty"`

	// b2b manage users
	B2bManageUsers bool `json:"b2b_manage_users,omitempty" yaml:"b2b_manage_users,omitempty"`

	// b2b read admin metadata
	B2bReadAdminMetadata bool `json:"b2b_read_admin_metadata,omitempty" yaml:"b2b_read_admin_metadata,omitempty"`

	// b2b read business metadata
	B2bReadBusinessMetadata bool `json:"b2b_read_business_metadata,omitempty" yaml:"b2b_read_business_metadata,omitempty"`

	// b2b read users
	B2bReadUsers bool `json:"b2b_read_users,omitempty" yaml:"b2b_read_users,omitempty"`

	// delete identity pool
	DeleteIdentityPool bool `json:"delete_identity_pool,omitempty" yaml:"delete_identity_pool,omitempty"`

	// get identity pool
	GetIdentityPool bool `json:"get_identity_pool,omitempty" yaml:"get_identity_pool,omitempty"`

	// manage identity pool users
	ManageIdentityPoolUsers bool `json:"manage_identity_pool_users,omitempty" yaml:"manage_identity_pool_users,omitempty"`

	// manage user addresses
	ManageUserAddresses bool `json:"manage_user_addresses,omitempty" yaml:"manage_user_addresses,omitempty"`

	// manage user identifiers
	ManageUserIdentifiers bool `json:"manage_user_identifiers,omitempty" yaml:"manage_user_identifiers,omitempty"`

	// manage user manager role
	ManageUserManagerRole bool `json:"manage_user_manager_role,omitempty" yaml:"manage_user_manager_role,omitempty"`

	// manage user otps
	ManageUserOtps bool `json:"manage_user_otps,omitempty" yaml:"manage_user_otps,omitempty"`

	// manage user passwords
	ManageUserPasswords bool `json:"manage_user_passwords,omitempty" yaml:"manage_user_passwords,omitempty"`

	// read identity pool users
	ReadIdentityPoolUsers bool `json:"read_identity_pool_users,omitempty" yaml:"read_identity_pool_users,omitempty"`

	// read roles
	ReadRoles bool `json:"read_roles,omitempty" yaml:"read_roles,omitempty"`

	// send user activation
	SendUserActivation bool `json:"send_user_activation,omitempty" yaml:"send_user_activation,omitempty"`

	// send user verification
	SendUserVerification bool `json:"send_user_verification,omitempty" yaml:"send_user_verification,omitempty"`

	// update identity pool
	UpdateIdentityPool bool `json:"update_identity_pool,omitempty" yaml:"update_identity_pool,omitempty"`
}

// Validate validates this pool permissions response
func (m *PoolPermissionsResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this pool permissions response based on context it is used
func (m *PoolPermissionsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PoolPermissionsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PoolPermissionsResponse) UnmarshalBinary(b []byte) error {
	var res PoolPermissionsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
