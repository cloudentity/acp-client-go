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

// GetServerDeveloperResponse get server developer response
//
// swagger:model GetServerDeveloperResponse
type GetServerDeveloperResponse struct {

	// Color
	// Example: #007FFF
	Color string `json:"color,omitempty"`

	// supported grant types
	// Example: ["implicit","authorization_code","refresh_token"]
	GrantTypes []string `json:"grant_types"`

	// authorization server id
	// Example: default
	ID string `json:"id,omitempty"`

	// issuer URL
	// Example: https://example.com/default/default
	IssuerURL string `json:"issuer_url,omitempty"`

	// mtls issuer url
	MtlsIssuerURL string `json:"mtls_issuer_url,omitempty"`

	// authorizations server name
	// Example: ACP
	Name string `json:"name,omitempty"`

	// supported subject identifier types
	// Example: ["public","pairwise"]
	SubjectIdentifierTypes []string `json:"subject_identifier_types"`
}

// Validate validates this get server developer response
func (m *GetServerDeveloperResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGrantTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjectIdentifierTypes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var getServerDeveloperResponseGrantTypesItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authorization_code","implicit","client_credentials","refresh_token","password","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:openid:params:grant-type:ciba","urn:ietf:params:oauth:grant-type:token-exchange"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getServerDeveloperResponseGrantTypesItemsEnum = append(getServerDeveloperResponseGrantTypesItemsEnum, v)
	}
}

func (m *GetServerDeveloperResponse) validateGrantTypesItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getServerDeveloperResponseGrantTypesItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GetServerDeveloperResponse) validateGrantTypes(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantTypes) { // not required
		return nil
	}

	for i := 0; i < len(m.GrantTypes); i++ {

		// value enum
		if err := m.validateGrantTypesItemsEnum("grant_types"+"."+strconv.Itoa(i), "body", m.GrantTypes[i]); err != nil {
			return err
		}

	}

	return nil
}

var getServerDeveloperResponseSubjectIdentifierTypesItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["public","pairwise"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		getServerDeveloperResponseSubjectIdentifierTypesItemsEnum = append(getServerDeveloperResponseSubjectIdentifierTypesItemsEnum, v)
	}
}

func (m *GetServerDeveloperResponse) validateSubjectIdentifierTypesItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, getServerDeveloperResponseSubjectIdentifierTypesItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *GetServerDeveloperResponse) validateSubjectIdentifierTypes(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjectIdentifierTypes) { // not required
		return nil
	}

	for i := 0; i < len(m.SubjectIdentifierTypes); i++ {

		// value enum
		if err := m.validateSubjectIdentifierTypesItemsEnum("subject_identifier_types"+"."+strconv.Itoa(i), "body", m.SubjectIdentifierTypes[i]); err != nil {
			return err
		}

	}

	return nil
}

// ContextValidate validates this get server developer response based on context it is used
func (m *GetServerDeveloperResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GetServerDeveloperResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetServerDeveloperResponse) UnmarshalBinary(b []byte) error {
	var res GetServerDeveloperResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
