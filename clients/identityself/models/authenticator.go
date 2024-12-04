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

// Authenticator authenticator
//
// swagger:model Authenticator
type Authenticator struct {

	// The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
	// identifier of the authenticator model being sought.
	AAGUID []uint8 `json:"AAGUID" yaml:"AAGUID"`

	// attachment
	Attachment AuthenticatorAttachment `json:"attachment,omitempty" yaml:"attachment,omitempty"`

	// CloneWarning - This is a signal that the authenticator may be cloned, i.e. at least two copies of the
	// credential private key may exist and are being used in parallel. Relying Parties should incorporate
	// this information into their risk scoring. Whether the Relying Party updates the stored signature
	// counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.
	CloneWarning bool `json:"cloneWarning,omitempty" yaml:"cloneWarning,omitempty"`

	// SignCount -Upon a new login operation, the Relying Party compares the stored signature counter value
	// with the new signCount value returned in the assertion’s authenticator data. If this new
	// signCount value is less than or equal to the stored value, a cloned authenticator may
	// exist, or the authenticator may be malfunctioning.
	SignCount uint32 `json:"signCount,omitempty" yaml:"signCount,omitempty"`
}

// Validate validates this authenticator
func (m *Authenticator) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttachment(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authenticator) validateAttachment(formats strfmt.Registry) error {
	if swag.IsZero(m.Attachment) { // not required
		return nil
	}

	if err := m.Attachment.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attachment")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("attachment")
		}
		return err
	}

	return nil
}

// ContextValidate validate this authenticator based on the context it is used
func (m *Authenticator) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttachment(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Authenticator) contextValidateAttachment(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Attachment) { // not required
		return nil
	}

	if err := m.Attachment.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("attachment")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("attachment")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Authenticator) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Authenticator) UnmarshalBinary(b []byte) error {
	var res Authenticator
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
