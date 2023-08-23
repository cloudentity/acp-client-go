// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// IntrospectOBBRDataAccessConsentV2Response introspect o b b r data access consent v2 response
//
// swagger:model IntrospectOBBRDataAccessConsentV2Response
type IntrospectOBBRDataAccessConsentV2Response struct {
	IntrospectResponse

	// account i ds
	AccountIDs []string `json:"AccountIDs"`

	// O consentId  o identificador nico do consentimento e dever ser um URN - Uniform Resource Name.
	// Um URN, conforme definido na [RFC8141](https://tools.ietf.org/html/rfc8141)  um Uniform Resource
	// Identifier - URI - que  atribudo sob o URI scheme "urn" e um namespace URN especfico, com a inteno de que o URN
	// seja um identificador de recurso persistente e independente da localizao.
	// Considerando a string urn:bancoex:C1DD33123 como exemplo para consentId temos:
	// o namespace(urn)
	// o identificador associado ao namespace da instituio transnmissora (bancoex)
	// o identificador especfico dentro do namespace (C1DD33123).
	// Informaes mais detalhadas sobre a construo de namespaces devem ser consultadas na [RFC8141](https://tools.ietf.org/html/rfc8141).
	// Example: urn:bancoex:C1DD33123
	// Required: true
	// Max Length: 256
	// Pattern: ^urn:[a-zA-Z0-9][a-zA-Z0-9-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$
	ConsentID *string `json:"consentId"`

	// Data e hora em que o recurso foi criado. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	CreationDateTime *strfmt.DateTime `json:"creationDateTime"`

	// document
	// Required: true
	Document *OpenbankingBrasilConsentV2Document1 `json:"document"`

	// Data e hora de expirao da permisso. De preenchimento obrigatrio, reflete a data limite de validade do consentimento. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	ExpirationDateTime *strfmt.DateTime `json:"expirationDateTime"`

	// Especifica os tipos de permisses de acesso s APIs no escopo do Open Banking Brasil - Fase 2, de acordo com os blocos de consentimento fornecidos pelo usurio e necessrios ao acesso a cada endpoint das APIs.
	// Example: ["ACCOUNTS_READ","ACCOUNTS_OVERDRAFT_LIMITS_READ","RESOURCES_READ"]
	// Required: true
	// Max Items: 30
	// Min Items: 1
	Permissions []OpenbankingBrasilConsentV2Permission1 `json:"permissions"`

	// rejection
	Rejection *OpenbankingBrasilConsentV2Rejection `json:"rejection,omitempty"`

	// status
	// Required: true
	Status *OpenbankingBrasilConsentV2Status `json:"status"`

	// Data e hora em que o recurso foi atualizado. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *IntrospectOBBRDataAccessConsentV2Response) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 IntrospectResponse
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.IntrospectResponse = aO0

	// AO1
	var dataAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		ConsentID *string `json:"consentId"`

		CreationDateTime *strfmt.DateTime `json:"creationDateTime"`

		Document *OpenbankingBrasilConsentV2Document1 `json:"document"`

		ExpirationDateTime *strfmt.DateTime `json:"expirationDateTime"`

		Permissions []OpenbankingBrasilConsentV2Permission1 `json:"permissions"`

		Rejection *OpenbankingBrasilConsentV2Rejection `json:"rejection,omitempty"`

		Status *OpenbankingBrasilConsentV2Status `json:"status"`

		StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.AccountIDs = dataAO1.AccountIDs

	m.ConsentID = dataAO1.ConsentID

	m.CreationDateTime = dataAO1.CreationDateTime

	m.Document = dataAO1.Document

	m.ExpirationDateTime = dataAO1.ExpirationDateTime

	m.Permissions = dataAO1.Permissions

	m.Rejection = dataAO1.Rejection

	m.Status = dataAO1.Status

	m.StatusUpdateDateTime = dataAO1.StatusUpdateDateTime

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m IntrospectOBBRDataAccessConsentV2Response) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		ConsentID *string `json:"consentId"`

		CreationDateTime *strfmt.DateTime `json:"creationDateTime"`

		Document *OpenbankingBrasilConsentV2Document1 `json:"document"`

		ExpirationDateTime *strfmt.DateTime `json:"expirationDateTime"`

		Permissions []OpenbankingBrasilConsentV2Permission1 `json:"permissions"`

		Rejection *OpenbankingBrasilConsentV2Rejection `json:"rejection,omitempty"`

		Status *OpenbankingBrasilConsentV2Status `json:"status"`

		StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime"`
	}

	dataAO1.AccountIDs = m.AccountIDs

	dataAO1.ConsentID = m.ConsentID

	dataAO1.CreationDateTime = m.CreationDateTime

	dataAO1.Document = m.Document

	dataAO1.ExpirationDateTime = m.ExpirationDateTime

	dataAO1.Permissions = m.Permissions

	dataAO1.Rejection = m.Rejection

	dataAO1.Status = m.Status

	dataAO1.StatusUpdateDateTime = m.StatusUpdateDateTime

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this introspect o b b r data access consent v2 response
func (m *IntrospectOBBRDataAccessConsentV2Response) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with IntrospectResponse
	if err := m.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDocument(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpirationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRejection(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdateDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateConsentID(formats strfmt.Registry) error {

	if err := validate.Required("consentId", "body", m.ConsentID); err != nil {
		return err
	}

	if err := validate.MaxLength("consentId", "body", *m.ConsentID, 256); err != nil {
		return err
	}

	if err := validate.Pattern("consentId", "body", *m.ConsentID, `^urn:[a-zA-Z0-9][a-zA-Z0-9-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$`); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateCreationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("creationDateTime", "body", m.CreationDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("creationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateDocument(formats strfmt.Registry) error {

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

func (m *IntrospectOBBRDataAccessConsentV2Response) validateExpirationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("expirationDateTime", "body", m.ExpirationDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("expirationDateTime", "body", "date-time", m.ExpirationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validatePermissions(formats strfmt.Registry) error {

	if err := validate.Required("permissions", "body", m.Permissions); err != nil {
		return err
	}

	iPermissionsSize := int64(len(m.Permissions))

	if err := validate.MinItems("permissions", "body", iPermissionsSize, 1); err != nil {
		return err
	}

	if err := validate.MaxItems("permissions", "body", iPermissionsSize, 30); err != nil {
		return err
	}

	for i := 0; i < len(m.Permissions); i++ {

		if err := m.Permissions[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateRejection(formats strfmt.Registry) error {

	if swag.IsZero(m.Rejection) { // not required
		return nil
	}

	if m.Rejection != nil {
		if err := m.Rejection.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rejection")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rejection")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	if m.Status != nil {
		if err := m.Status.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("status")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("status")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) validateStatusUpdateDateTime(formats strfmt.Registry) error {

	if err := validate.Required("statusUpdateDateTime", "body", m.StatusUpdateDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("statusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this introspect o b b r data access consent v2 response based on the context it is used
func (m *IntrospectOBBRDataAccessConsentV2Response) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with IntrospectResponse
	if err := m.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDocument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePermissions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRejection(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) contextValidateDocument(ctx context.Context, formats strfmt.Registry) error {

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

func (m *IntrospectOBBRDataAccessConsentV2Response) contextValidatePermissions(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Permissions); i++ {

		if swag.IsZero(m.Permissions[i]) { // not required
			return nil
		}

		if err := m.Permissions[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) contextValidateRejection(ctx context.Context, formats strfmt.Registry) error {

	if m.Rejection != nil {

		if swag.IsZero(m.Rejection) { // not required
			return nil
		}

		if err := m.Rejection.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rejection")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rejection")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRDataAccessConsentV2Response) contextValidateStatus(ctx context.Context, formats strfmt.Registry) error {

	if m.Status != nil {

		if err := m.Status.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("status")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("status")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IntrospectOBBRDataAccessConsentV2Response) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IntrospectOBBRDataAccessConsentV2Response) UnmarshalBinary(b []byte) error {
	var res IntrospectOBBRDataAccessConsentV2Response
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
