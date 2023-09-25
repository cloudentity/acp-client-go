// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// Duration A Duration represents the elapsed time between two instants
// as an int64 nanosecond count. The representation limits the
// largest representable duration to approximately 290 years.
//
// swagger:model Duration
type Duration int64

// Validate validates this duration
func (m Duration) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this duration based on context it is used
func (m Duration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
