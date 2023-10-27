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

// OpenbankingBrasilConsentV2BusinessEntityExtends OpenbankingBrasilConsentV2BusinessEntityExtends BusinessEntityExtends
//
// Titular, pessoa jurdica a quem se referem os dados que so objeto de compartilhamento.
// Deve ser informado apenas para casos de consentimento pessoa jurdica.
// No precisa ser armazenado separadamente. Para fins de renovao de consentimento, ser utilizado apenas para verificao do consentimento vigente, pois  um atributo imutvel.
//
// swagger:model OpenbankingBrasilConsentV2BusinessEntityExtends
type OpenbankingBrasilConsentV2BusinessEntityExtends struct {

	// document
	// Required: true
	Document *OpenbankingBrasilConsentV2BusinessEntityDocument `json:"document"`
}

// Validate validates this openbanking brasil consent v2 business entity extends
func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDocument(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) validateDocument(formats strfmt.Registry) error {

	if err := validate.Required("document", "body", m.Document); err != nil {
		return err
	}

	if m.Document != nil {
		if err := m.Document.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("document")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("document")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking brasil consent v2 business entity extends based on the context it is used
func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDocument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) contextValidateDocument(ctx context.Context, formats strfmt.Registry) error {

	if m.Document != nil {

		if err := m.Document.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("document")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("document")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilConsentV2BusinessEntityExtends) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilConsentV2BusinessEntityExtends
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
