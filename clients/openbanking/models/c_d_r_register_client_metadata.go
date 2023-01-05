// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CDRRegisterClientMetadata c d r register client metadata
//
// swagger:model CDRRegisterClientMetadata
type CDRRegisterClientMetadata struct {

	// data recipient status
	DataRecipientStatus string `json:"data_recipient_status,omitempty"`

	// software product status
	SoftwareProductStatus string `json:"software_product_status,omitempty"`
}

// Validate validates this c d r register client metadata
func (m *CDRRegisterClientMetadata) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this c d r register client metadata based on context it is used
func (m *CDRRegisterClientMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CDRRegisterClientMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CDRRegisterClientMetadata) UnmarshalBinary(b []byte) error {
	var res CDRRegisterClientMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
