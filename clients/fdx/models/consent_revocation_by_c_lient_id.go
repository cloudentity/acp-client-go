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

// ConsentRevocationByCLientID consent revocation by c lient ID
//
// swagger:model ConsentRevocationByCLientID
type ConsentRevocationByCLientID struct {

	// revocation details
	RevocationDetails *FDXConsentRevocation `json:"RevocationDetails,omitempty"`

	// Client ID
	ClientID string `json:"client_id,omitempty"`
}

// Validate validates this consent revocation by c lient ID
func (m *ConsentRevocationByCLientID) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRevocationDetails(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentRevocationByCLientID) validateRevocationDetails(formats strfmt.Registry) error {
	if swag.IsZero(m.RevocationDetails) { // not required
		return nil
	}

	if m.RevocationDetails != nil {
		if err := m.RevocationDetails.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RevocationDetails")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("RevocationDetails")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this consent revocation by c lient ID based on the context it is used
func (m *ConsentRevocationByCLientID) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRevocationDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentRevocationByCLientID) contextValidateRevocationDetails(ctx context.Context, formats strfmt.Registry) error {

	if m.RevocationDetails != nil {
		if err := m.RevocationDetails.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("RevocationDetails")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("RevocationDetails")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConsentRevocationByCLientID) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentRevocationByCLientID) UnmarshalBinary(b []byte) error {
	var res ConsentRevocationByCLientID
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
