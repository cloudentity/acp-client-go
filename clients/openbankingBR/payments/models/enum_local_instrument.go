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

// EnumLocalInstrument EnumLocalInstrument
//
// Especifica a forma de iniciao do pagamento:
// - MANU - Insero manual de dados da conta transacional
// - DICT - Insero manual de chave Pix
// - QRDN - QR code dinmico
// - QRES - QR code esttico
// - INIC - Indica que o recebedor (creditor) contratou o Iniciador de Pagamentos especificamente para realizar iniciaes de pagamento em que o beneficirio  previamente conhecido.
//
// swagger:model EnumLocalInstrument
type EnumLocalInstrument string

func NewEnumLocalInstrument(value EnumLocalInstrument) *EnumLocalInstrument {
	return &value
}

// Pointer returns a pointer to a freshly-allocated EnumLocalInstrument.
func (m EnumLocalInstrument) Pointer() *EnumLocalInstrument {
	return &m
}

const (

	// EnumLocalInstrumentMANU captures enum value "MANU"
	EnumLocalInstrumentMANU EnumLocalInstrument = "MANU"

	// EnumLocalInstrumentDICT captures enum value "DICT"
	EnumLocalInstrumentDICT EnumLocalInstrument = "DICT"

	// EnumLocalInstrumentQRDN captures enum value "QRDN"
	EnumLocalInstrumentQRDN EnumLocalInstrument = "QRDN"

	// EnumLocalInstrumentQRES captures enum value "QRES"
	EnumLocalInstrumentQRES EnumLocalInstrument = "QRES"

	// EnumLocalInstrumentINIC captures enum value "INIC"
	EnumLocalInstrumentINIC EnumLocalInstrument = "INIC"
)

// for schema
var enumLocalInstrumentEnum []interface{}

func init() {
	var res []EnumLocalInstrument
	if err := json.Unmarshal([]byte(`["MANU","DICT","QRDN","QRES","INIC"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		enumLocalInstrumentEnum = append(enumLocalInstrumentEnum, v)
	}
}

func (m EnumLocalInstrument) validateEnumLocalInstrumentEnum(path, location string, value EnumLocalInstrument) error {
	if err := validate.EnumCase(path, location, value, enumLocalInstrumentEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this enum local instrument
func (m EnumLocalInstrument) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateEnumLocalInstrumentEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this enum local instrument based on context it is used
func (m EnumLocalInstrument) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
