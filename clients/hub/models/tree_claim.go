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

// TreeClaim tree claim
//
// swagger:model TreeClaim
type TreeClaim struct {

	// description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// DeprecatedMapping use SourceType and SourcePath instead
	// claim mapping - path to attribute in authentication context from where claim value should be picked
	// Example: email
	Mapping string `json:"mapping,omitempty" yaml:"mapping,omitempty"`

	// included in userinfo/introspect endpoints only
	Opaque bool `json:"opaque,omitempty" yaml:"opaque,omitempty"`

	// saml name
	// Example: email
	SamlName string `json:"saml_name,omitempty" yaml:"saml_name,omitempty"`

	// saml name format
	// Example: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
	SamlNameFormat string `json:"saml_name_format,omitempty" yaml:"saml_name_format,omitempty"`

	// list of scopes - when at least one of listed scopes has been granted to a client, then claim will be added to id / access token.
	// In case of empty array claim is always added.
	// Example: ["email","email_verified"]
	Scopes []string `json:"scopes" yaml:"scopes"`

	// path to the attribute in source type context where claim value should be picked from
	SourcePath string `json:"source_path,omitempty" yaml:"source_path,omitempty"`

	// source type
	SourceType ClaimSourceType `json:"source_type,omitempty" yaml:"source_type,omitempty"`

	// mark claim as verified (required by identity assurance spec)
	Verified bool `json:"verified,omitempty" yaml:"verified,omitempty"`
}

// Validate validates this tree claim
func (m *TreeClaim) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSourceType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeClaim) validateSourceType(formats strfmt.Registry) error {
	if swag.IsZero(m.SourceType) { // not required
		return nil
	}

	if err := m.SourceType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("source_type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("source_type")
		}
		return err
	}

	return nil
}

// ContextValidate validate this tree claim based on the context it is used
func (m *TreeClaim) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSourceType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeClaim) contextValidateSourceType(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.SourceType) { // not required
		return nil
	}

	if err := m.SourceType.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("source_type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("source_type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreeClaim) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeClaim) UnmarshalBinary(b []byte) error {
	var res TreeClaim
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
