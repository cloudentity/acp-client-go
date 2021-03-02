// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PolicyDependency policy dependency
//
// swagger:model PolicyDependency
type PolicyDependency struct {

	// embedded policy ID
	EmbeddedPolicyID string `json:"embedded_policy_id,omitempty"`

	// policy ID
	PolicyID string `json:"policy_id,omitempty"`

	// server ID
	ServerID string `json:"server_id,omitempty"`

	// tenant ID
	TenantID string `json:"tenant_id,omitempty"`
}

// Validate validates this policy dependency
func (m *PolicyDependency) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this policy dependency based on context it is used
func (m *PolicyDependency) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PolicyDependency) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PolicyDependency) UnmarshalBinary(b []byte) error {
	var res PolicyDependency
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
