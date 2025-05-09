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

// OrganizationResponse organization response
//
// swagger:model OrganizationResponse
type OrganizationResponse struct {

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

	// issuer url
	IssuerURL string `json:"issuer_url,omitempty" yaml:"issuer_url,omitempty"`

	// metadata
	Metadata *ServerMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Display name of the organization
	// Example: default
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// number of child organizations
	NumberOfChildOrganizations int64 `json:"number_of_child_organizations,omitempty" yaml:"number_of_child_organizations,omitempty"`

	// The id of the parent workspace / organization
	ParentID string `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`

	// subject format
	// Enum: ["hash","legacy"]
	SubjectFormat string `json:"subject_format,omitempty" yaml:"subject_format,omitempty"`

	// subject identifier algorithm salt
	SubjectIdentifierAlgorithmSalt string `json:"subject_identifier_algorithm_salt,omitempty" yaml:"subject_identifier_algorithm_salt,omitempty"`

	// If true this organization can be used as a template when creating a new ones.
	Template bool `json:"template,omitempty" yaml:"template,omitempty"`

	// theme id
	ThemeID string `json:"theme_id,omitempty" yaml:"theme_id,omitempty"`
}

// Validate validates this organization response
func (m *OrganizationResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjectFormat(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var organizationResponseAuthenticationMechanismsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","email_otp","sms_otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		organizationResponseAuthenticationMechanismsItemsEnum = append(organizationResponseAuthenticationMechanismsItemsEnum, v)
	}
}

func (m *OrganizationResponse) validateAuthenticationMechanismsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, organizationResponseAuthenticationMechanismsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OrganizationResponse) validateAuthenticationMechanisms(formats strfmt.Registry) error {
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

func (m *OrganizationResponse) validateMetadata(formats strfmt.Registry) error {
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

var organizationResponseTypeSubjectFormatPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["hash","legacy"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		organizationResponseTypeSubjectFormatPropEnum = append(organizationResponseTypeSubjectFormatPropEnum, v)
	}
}

const (

	// OrganizationResponseSubjectFormatHash captures enum value "hash"
	OrganizationResponseSubjectFormatHash string = "hash"

	// OrganizationResponseSubjectFormatLegacy captures enum value "legacy"
	OrganizationResponseSubjectFormatLegacy string = "legacy"
)

// prop value enum
func (m *OrganizationResponse) validateSubjectFormatEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, organizationResponseTypeSubjectFormatPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OrganizationResponse) validateSubjectFormat(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjectFormat) { // not required
		return nil
	}

	// value enum
	if err := m.validateSubjectFormatEnum("subject_format", "body", m.SubjectFormat); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this organization response based on the context it is used
func (m *OrganizationResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OrganizationResponse) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OrganizationResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OrganizationResponse) UnmarshalBinary(b []byte) error {
	var res OrganizationResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
