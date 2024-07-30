// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// UserMFASession user m f a session
//
// swagger:model UserMFASession
type UserMFASession struct {

	// Session id
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// IP address of the user who created the session
	IPAddress string `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`

	// Time when the session was issued
	// Format: date-time
	IssueTime strfmt.DateTime `json:"issue_time,omitempty" yaml:"issue_time,omitempty"`

	// User agent of the user who created the session
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
}

// Validate validates this user m f a session
func (m *UserMFASession) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIssueTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserMFASession) validateIssueTime(formats strfmt.Registry) error {
	if swag.IsZero(m.IssueTime) { // not required
		return nil
	}

	if err := validate.FormatOf("issue_time", "body", "date-time", m.IssueTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this user m f a session based on context it is used
func (m *UserMFASession) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UserMFASession) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserMFASession) UnmarshalBinary(b []byte) error {
	var res UserMFASession
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
