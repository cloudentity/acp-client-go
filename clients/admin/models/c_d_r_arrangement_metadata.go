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

// CDRArrangementMetadata c d r arrangement metadata
//
// swagger:model CDRArrangementMetadata
type CDRArrangementMetadata struct {

	// personal details
	PersonalDetails PersonalDetails `json:"personal_details,omitempty"`

	// revocation channel
	RevocationChannel RevocationChannel `json:"revocation_channel,omitempty"`

	// revocation reason
	RevocationReason RevocationReason `json:"revocation_reason,omitempty"`
}

// Validate validates this c d r arrangement metadata
func (m *CDRArrangementMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePersonalDetails(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevocationChannel(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevocationReason(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CDRArrangementMetadata) validatePersonalDetails(formats strfmt.Registry) error {
	if swag.IsZero(m.PersonalDetails) { // not required
		return nil
	}

	if m.PersonalDetails != nil {
		if err := m.PersonalDetails.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("personal_details")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("personal_details")
			}
			return err
		}
	}

	return nil
}

func (m *CDRArrangementMetadata) validateRevocationChannel(formats strfmt.Registry) error {
	if swag.IsZero(m.RevocationChannel) { // not required
		return nil
	}

	if err := m.RevocationChannel.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("revocation_channel")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("revocation_channel")
		}
		return err
	}

	return nil
}

func (m *CDRArrangementMetadata) validateRevocationReason(formats strfmt.Registry) error {
	if swag.IsZero(m.RevocationReason) { // not required
		return nil
	}

	if err := m.RevocationReason.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("revocation_reason")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("revocation_reason")
		}
		return err
	}

	return nil
}

// ContextValidate validate this c d r arrangement metadata based on the context it is used
func (m *CDRArrangementMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePersonalDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevocationChannel(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevocationReason(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CDRArrangementMetadata) contextValidatePersonalDetails(ctx context.Context, formats strfmt.Registry) error {

	if err := m.PersonalDetails.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("personal_details")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("personal_details")
		}
		return err
	}

	return nil
}

func (m *CDRArrangementMetadata) contextValidateRevocationChannel(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RevocationChannel.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("revocation_channel")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("revocation_channel")
		}
		return err
	}

	return nil
}

func (m *CDRArrangementMetadata) contextValidateRevocationReason(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RevocationReason.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("revocation_reason")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("revocation_reason")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CDRArrangementMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CDRArrangementMetadata) UnmarshalBinary(b []byte) error {
	var res CDRArrangementMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
