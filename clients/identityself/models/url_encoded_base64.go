// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// URLEncodedBase64 URLEncodedBase64 represents a byte slice holding URL-encoded base64 data.
//
// When fields of this type are unmarshalled from JSON, the data is base64
// decoded into a byte slice.
//
// swagger:model URLEncodedBase64
type URLEncodedBase64 []uint8

// Validate validates this URL encoded base64
func (m URLEncodedBase64) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this URL encoded base64 based on context it is used
func (m URLEncodedBase64) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
