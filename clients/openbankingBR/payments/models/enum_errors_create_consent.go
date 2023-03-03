// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// EnumErrorsCreateConsent EnumErrorsCreateConsent
//
// Cdigos de erros previstos na criao de consentimento para a iniciao de pagamentos:
//
//	FORMA_PGTO_INVALIDA: Forma de pagamento invlida.
//	DATA_PGTO_INVALIDA: Data de pagamento invlida.
//	DETALHE_PGTO_INVALIDO: Detalhe do pagamento invlido.
//	NAO_INFORMADO: No informado.
//
// swagger:model EnumErrorsCreateConsent
type EnumErrorsCreateConsent string

func NewEnumErrorsCreateConsent(value EnumErrorsCreateConsent) *EnumErrorsCreateConsent {
	return &value
}

// Pointer returns a pointer to a freshly-allocated EnumErrorsCreateConsent.
func (m EnumErrorsCreateConsent) Pointer() *EnumErrorsCreateConsent {
	return &m
}

const (

	// EnumErrorsCreateConsentFORMAPGTOINVALIDA captures enum value "FORMA_PGTO_INVALIDA"
	EnumErrorsCreateConsentFORMAPGTOINVALIDA EnumErrorsCreateConsent = "FORMA_PGTO_INVALIDA"

	// EnumErrorsCreateConsentDATAPGTOINVALIDA captures enum value "DATA_PGTO_INVALIDA"
	EnumErrorsCreateConsentDATAPGTOINVALIDA EnumErrorsCreateConsent = "DATA_PGTO_INVALIDA"

	// EnumErrorsCreateConsentDETALHEPGTOINVALIDO captures enum value "DETALHE_PGTO_INVALIDO"
	EnumErrorsCreateConsentDETALHEPGTOINVALIDO EnumErrorsCreateConsent = "DETALHE_PGTO_INVALIDO"

	// EnumErrorsCreateConsentNAOINFORMADO captures enum value "NAO_INFORMADO"
	EnumErrorsCreateConsentNAOINFORMADO EnumErrorsCreateConsent = "NAO_INFORMADO"
)

// for schema
var enumErrorsCreateConsentEnum []interface{}

func init() {
	var res []EnumErrorsCreateConsent
	if err := json.Unmarshal([]byte(`["FORMA_PGTO_INVALIDA","DATA_PGTO_INVALIDA","DETALHE_PGTO_INVALIDO","NAO_INFORMADO"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		enumErrorsCreateConsentEnum = append(enumErrorsCreateConsentEnum, v)
	}
}

func (m EnumErrorsCreateConsent) validateEnumErrorsCreateConsentEnum(path, location string, value EnumErrorsCreateConsent) error {
	if err := validate.EnumCase(path, location, value, enumErrorsCreateConsentEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this enum errors create consent
func (m EnumErrorsCreateConsent) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateEnumErrorsCreateConsentEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this enum errors create consent based on context it is used
func (m EnumErrorsCreateConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
