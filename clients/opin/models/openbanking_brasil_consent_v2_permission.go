// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilConsentV2Permission OpenbankingBrasilConsentV2Permission Permission
//
// Especifica os tipos de permisses de acesso s APIs no escopo do Open Banking Brasil - Fase 2, de acordo com os blocos de consentimento fornecidos pelo usurio e necessrios ao acesso a cada endpoint das APIs.
//
// swagger:model OpenbankingBrasilConsentV2Permission
type OpenbankingBrasilConsentV2Permission string

// Validate validates this openbanking brasil consent v2 permission
func (m OpenbankingBrasilConsentV2Permission) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil consent v2 permission based on context it is used
func (m OpenbankingBrasilConsentV2Permission) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
