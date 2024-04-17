// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TreeScope tree scope
//
// swagger:model TreeScope
type TreeScope struct {

	// The scope description displayed as a hint on a consent page
	// Example: This scope value requests offline access using refresh token
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// The scope name displayed on a consent page
	// Example: Offline Access
	DisplayName string `json:"display_name,omitempty" yaml:"display_name,omitempty"`

	// Request this scope by default for all clients who subscribed to this scope
	Implicit bool `json:"implicit,omitempty" yaml:"implicit,omitempty"`

	// Do not ask for consent for this scope
	ImplicitGrant bool `json:"implicit_grant,omitempty" yaml:"implicit_grant,omitempty"`

	// metadata
	Metadata Metadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// policy execution points
	PolicyExecutionPoints TreePolicyExecutionPoints `json:"policy_execution_points,omitempty" yaml:"policy_execution_points,omitempty"`

	// Disable storage of scope grants
	Transient bool `json:"transient,omitempty" yaml:"transient,omitempty"`
}

// Validate validates this tree scope
func (m *TreeScope) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyExecutionPoints(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeScope) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

func (m *TreeScope) validatePolicyExecutionPoints(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicyExecutionPoints) { // not required
		return nil
	}

	if m.PolicyExecutionPoints != nil {
		if err := m.PolicyExecutionPoints.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy_execution_points")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy_execution_points")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tree scope based on the context it is used
func (m *TreeScope) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicyExecutionPoints(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeScope) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("metadata")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("metadata")
		}
		return err
	}

	return nil
}

func (m *TreeScope) contextValidatePolicyExecutionPoints(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PolicyExecutionPoints) { // not required
		return nil
	}

	if err := m.PolicyExecutionPoints.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("policy_execution_points")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("policy_execution_points")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreeScope) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeScope) UnmarshalBinary(b []byte) error {
	var res TreeScope
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
