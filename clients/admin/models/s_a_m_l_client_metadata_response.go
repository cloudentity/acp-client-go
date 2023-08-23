// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SAMLClientMetadataResponse s a m l client metadata response
//
// swagger:model SAMLClientMetadataResponse
type SAMLClientMetadataResponse struct {

	// in:body
	RawXML string `json:"raw_xml,omitempty"`
}

// Validate validates this s a m l client metadata response
func (m *SAMLClientMetadataResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this s a m l client metadata response based on context it is used
func (m *SAMLClientMetadataResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLClientMetadataResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLClientMetadataResponse) UnmarshalBinary(b []byte) error {
	var res SAMLClientMetadataResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}