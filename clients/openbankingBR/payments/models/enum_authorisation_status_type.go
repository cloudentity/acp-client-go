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

// EnumAuthorisationStatusType EnumAuthorisationStatusType
//
// Retorna o estado do consentimento, o qual no momento de sua criao ser AWAITING_AUTHORISATION.
// Este estado ser alterado depois da autorizao do consentimento na detentora da conta do pagador (Debtor) para AUTHORISED ou REJECTED.
// O consentimento fica no estado CONSUMED aps ocorrer a iniciao do pagamento referente ao consentimento.
// Em caso de consentimento expirado a detentora dever retornar o status REJECTED.
// Estados possveis:
// AWAITING_AUTHORISATION - Aguardando autorizao
// AUTHORISED - Autorizado
// REJECTED - Rejeitado
// CONSUMED - Consumido
//
// swagger:model EnumAuthorisationStatusType
type EnumAuthorisationStatusType string

func NewEnumAuthorisationStatusType(value EnumAuthorisationStatusType) *EnumAuthorisationStatusType {
	return &value
}

// Pointer returns a pointer to a freshly-allocated EnumAuthorisationStatusType.
func (m EnumAuthorisationStatusType) Pointer() *EnumAuthorisationStatusType {
	return &m
}

const (

	// EnumAuthorisationStatusTypeAWAITINGAUTHORISATION captures enum value "AWAITING_AUTHORISATION"
	EnumAuthorisationStatusTypeAWAITINGAUTHORISATION EnumAuthorisationStatusType = "AWAITING_AUTHORISATION"

	// EnumAuthorisationStatusTypeAUTHORISED captures enum value "AUTHORISED"
	EnumAuthorisationStatusTypeAUTHORISED EnumAuthorisationStatusType = "AUTHORISED"

	// EnumAuthorisationStatusTypeREJECTED captures enum value "REJECTED"
	EnumAuthorisationStatusTypeREJECTED EnumAuthorisationStatusType = "REJECTED"

	// EnumAuthorisationStatusTypeCONSUMED captures enum value "CONSUMED"
	EnumAuthorisationStatusTypeCONSUMED EnumAuthorisationStatusType = "CONSUMED"
)

// for schema
var enumAuthorisationStatusTypeEnum []interface{}

func init() {
	var res []EnumAuthorisationStatusType
	if err := json.Unmarshal([]byte(`["AWAITING_AUTHORISATION","AUTHORISED","REJECTED","CONSUMED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		enumAuthorisationStatusTypeEnum = append(enumAuthorisationStatusTypeEnum, v)
	}
}

func (m EnumAuthorisationStatusType) validateEnumAuthorisationStatusTypeEnum(path, location string, value EnumAuthorisationStatusType) error {
	if err := validate.EnumCase(path, location, value, enumAuthorisationStatusTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this enum authorisation status type
func (m EnumAuthorisationStatusType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateEnumAuthorisationStatusTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this enum authorisation status type based on context it is used
func (m EnumAuthorisationStatusType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
