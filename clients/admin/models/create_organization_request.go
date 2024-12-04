// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// CreateOrganizationRequest create organization request
//
// swagger:model CreateOrganizationRequest
type CreateOrganizationRequest struct {

	// allowed authentication mechanisms
	AuthenticationMechanisms []string `json:"authentication_mechanisms" yaml:"authentication_mechanisms"`

	// Your organization's label color in a HEX format.
	// Example: #007FFF
	Color string `json:"color,omitempty" yaml:"color,omitempty"`

	// Display description of the organization
	// Example: Organization description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// An array of email domains configured for an organization for the purposes of IDP discovery
	Domains []string `json:"domains" yaml:"domains"`

	// Unique identifier of an organization
	//
	// If not provided, a random ID is generated.
	// Example: default
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// metadata
	Metadata *ServerMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Display name of the organization
	// Example: default
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// The id of the parent workspace / organization
	ParentID string `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`

	// If true this organization can be used as a template when creating a new ones.
	Template bool `json:"template,omitempty" yaml:"template,omitempty"`

	// The id of the organization template that should be used to create the new organization
	TemplateID string `json:"template_id,omitempty" yaml:"template_id,omitempty"`
}

// Validate validates this create organization request
func (m *CreateOrganizationRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var createOrganizationRequestAuthenticationMechanismsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		createOrganizationRequestAuthenticationMechanismsItemsEnum = append(createOrganizationRequestAuthenticationMechanismsItemsEnum, v)
	}
}

func (m *CreateOrganizationRequest) validateAuthenticationMechanismsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, createOrganizationRequestAuthenticationMechanismsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CreateOrganizationRequest) validateAuthenticationMechanisms(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationMechanisms) { // not required
		return nil
	}

	for i := 0; i < len(m.AuthenticationMechanisms); i++ {

		// value enum
		if err := m.validateAuthenticationMechanismsItemsEnum("authentication_mechanisms"+"."+strconv.Itoa(i), "body", m.AuthenticationMechanisms[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *CreateOrganizationRequest) validateMetadata(formats strfmt.Registry) error {
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

// ContextValidate validate this create organization request based on the context it is used
func (m *CreateOrganizationRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateOrganizationRequest) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.Metadata != nil {

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
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CreateOrganizationRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreateOrganizationRequest) UnmarshalBinary(b []byte) error {
	var res CreateOrganizationRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
