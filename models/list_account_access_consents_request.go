// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ListAccountAccessConsentsRequest list account access consents request
//
// swagger:model ListAccountAccessConsentsRequest
type ListAccountAccessConsentsRequest struct {

	// optional list of account
	AccountIDs []string `json:"accounts"`

	// optional client ID
	ClientID string `json:"client_id,omitempty"`
}

// Validate validates this list account access consents request
func (m *ListAccountAccessConsentsRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this list account access consents request based on context it is used
func (m *ListAccountAccessConsentsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ListAccountAccessConsentsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ListAccountAccessConsentsRequest) UnmarshalBinary(b []byte) error {
	var res ListAccountAccessConsentsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
