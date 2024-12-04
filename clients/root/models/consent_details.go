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

// ConsentDetails consent details
//
// swagger:model ConsentDetails
type ConsentDetails struct {

	// br
	Br *BRConsentPayload `json:"br,omitempty" yaml:"br,omitempty"`

	// cdr
	Cdr *CDRArrangement `json:"cdr,omitempty" yaml:"cdr,omitempty"`

	// cdr previous
	CdrPrevious *CDRArrangement `json:"cdr_previous,omitempty" yaml:"cdr_previous,omitempty"`

	// fdx
	Fdx *FDXConsent `json:"fdx,omitempty" yaml:"fdx,omitempty"`

	// uk
	Uk *UKConsentPayload `json:"uk,omitempty" yaml:"uk,omitempty"`
}

// Validate validates this consent details
func (m *ConsentDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBr(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCdr(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCdrPrevious(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFdx(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUk(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentDetails) validateBr(formats strfmt.Registry) error {
	if swag.IsZero(m.Br) { // not required
		return nil
	}

	if m.Br != nil {
		if err := m.Br.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("br")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("br")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) validateCdr(formats strfmt.Registry) error {
	if swag.IsZero(m.Cdr) { // not required
		return nil
	}

	if m.Cdr != nil {
		if err := m.Cdr.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdr")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdr")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) validateCdrPrevious(formats strfmt.Registry) error {
	if swag.IsZero(m.CdrPrevious) { // not required
		return nil
	}

	if m.CdrPrevious != nil {
		if err := m.CdrPrevious.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdr_previous")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdr_previous")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) validateFdx(formats strfmt.Registry) error {
	if swag.IsZero(m.Fdx) { // not required
		return nil
	}

	if m.Fdx != nil {
		if err := m.Fdx.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdx")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdx")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) validateUk(formats strfmt.Registry) error {
	if swag.IsZero(m.Uk) { // not required
		return nil
	}

	if m.Uk != nil {
		if err := m.Uk.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("uk")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("uk")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this consent details based on the context it is used
func (m *ConsentDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBr(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCdr(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCdrPrevious(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFdx(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUk(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConsentDetails) contextValidateBr(ctx context.Context, formats strfmt.Registry) error {

	if m.Br != nil {

		if swag.IsZero(m.Br) { // not required
			return nil
		}

		if err := m.Br.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("br")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("br")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) contextValidateCdr(ctx context.Context, formats strfmt.Registry) error {

	if m.Cdr != nil {

		if swag.IsZero(m.Cdr) { // not required
			return nil
		}

		if err := m.Cdr.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdr")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdr")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) contextValidateCdrPrevious(ctx context.Context, formats strfmt.Registry) error {

	if m.CdrPrevious != nil {

		if swag.IsZero(m.CdrPrevious) { // not required
			return nil
		}

		if err := m.CdrPrevious.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdr_previous")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdr_previous")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) contextValidateFdx(ctx context.Context, formats strfmt.Registry) error {

	if m.Fdx != nil {

		if swag.IsZero(m.Fdx) { // not required
			return nil
		}

		if err := m.Fdx.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdx")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdx")
			}
			return err
		}
	}

	return nil
}

func (m *ConsentDetails) contextValidateUk(ctx context.Context, formats strfmt.Registry) error {

	if m.Uk != nil {

		if swag.IsZero(m.Uk) { // not required
			return nil
		}

		if err := m.Uk.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("uk")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("uk")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConsentDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConsentDetails) UnmarshalBinary(b []byte) error {
	var res ConsentDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
