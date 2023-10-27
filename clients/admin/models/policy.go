// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Policy policy
//
// swagger:model Policy
type Policy struct {

	// The definition of an Open Policy Agent (OPA) policy provided using the REGO language.
	Definition string `json:"definition,omitempty"`

	// Unique ID of your policy
	// Example: 1
	ID string `json:"id,omitempty"`

	// Language of a policy
	//
	// ACP supports creating Cloudentity policies (using a visual editor or defined using JSON or
	// YAML) and policies defined using REGO (language used by Open Policy Agent (OPA)).
	// Example: cloudentity
	Language string `json:"language,omitempty"`

	// Display name for your policy
	// Example: check_consent
	PolicyName string `json:"policy_name,omitempty"`

	// ID of your authorization server (workspace)
	// Example: default
	ServerID string `json:"server_id,omitempty"`

	// ID of your tenant
	// Example: default
	TenantID string `json:"tenant_id,omitempty"`

	// Define a type of your policy
	//
	// ACP is provided with the following policy types: user, developer, machine, dcr, api.
	//
	// Depending on the policy type the policy can be assigned to different policy
	// execution points.
	//
	// A policy of the `user` type can be assigned only to the following scopes: `scope_user_grant`,
	// `server_user_token`, `client_user_token`.
	//
	// A `developer` policy can be assigned only to the `scope_client_assignment` and
	// `server_client_assignment` scopes.
	//
	// A policy of the `machine` type can be assigned only to the following scopes:
	// `scope_machine_grant`, `server_machine_token`, `client_machine_token`.
	//
	// A `dcr` policy can be assigned only to the `scope_dynamic_client_registration` and the
	// `server_dynamic_client_registration` scopes.
	//
	// An `api` policy can be assigned to all of the policy execution points.
	//
	// Each of the policies type has its defined and provided out of the box policy validators.
	// Example: user
	Type string `json:"type,omitempty"`

	// An array of validators for a Cloudentity policy
	Validators []*ValidatorConfig `json:"validators"`
}

// Validate validates this policy
func (m *Policy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateValidators(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Policy) validateValidators(formats strfmt.Registry) error {
	if swag.IsZero(m.Validators) { // not required
		return nil
	}

	for i := 0; i < len(m.Validators); i++ {
		if swag.IsZero(m.Validators[i]) { // not required
			continue
		}

		if m.Validators[i] != nil {
			if err := m.Validators[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("validators" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("validators" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this policy based on the context it is used
func (m *Policy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateValidators(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Policy) contextValidateValidators(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Validators); i++ {

		if m.Validators[i] != nil {

			if swag.IsZero(m.Validators[i]) { // not required
				return nil
			}

			if err := m.Validators[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("validators" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("validators" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Policy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Policy) UnmarshalBinary(b []byte) error {
	var res Policy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
