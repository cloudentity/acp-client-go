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

// IntrospectOBBRAutomaticPaymentsRecurringConsentResponse introspect o b b r automatic payments recurring consent response
//
// swagger:model IntrospectOBBRAutomaticPaymentsRecurringConsentResponse
type IntrospectOBBRAutomaticPaymentsRecurringConsentResponse struct {
	IntrospectResponse

	// account i ds
	AccountIDs []string `json:"AccountIDs" yaml:"AccountIDs"`

	// Deve ser preenchido sempre que o usurio pagador inserir alguma informao adicional no consentimento
	// Example: Minha recorrncia
	// Max Length: 140
	// Pattern: [\w\W\s]*
	AdditionalInformation string `json:"additionalInformation,omitempty" yaml:"additionalInformation,omitempty"`

	// business entity
	BusinessEntity *OpenbankingBrasilAutomaticPaymentV1BusinessEntity `json:"businessEntity,omitempty" yaml:"businessEntity,omitempty"`

	// Data e hora em que o consentimento foi criado. Uma string com data e hora conforme especificao [RFC-3339](https://datatracker.ietf.org/doc/html/rfc3339), sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	CreationDateTime *strfmt.DateTime `json:"creationDateTime" yaml:"creationDateTime"`

	// creditors
	// Required: true
	// Min Items: 1
	Creditors []*OpenbankingBrasilAutomaticPaymentV1Creditor `json:"creditors" yaml:"creditors"`

	// debtor account
	DebtorAccount *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount `json:"debtorAccount,omitempty" yaml:"debtorAccount,omitempty"`

	// Data e hora em que o consentimento deve deixar de ser vlido. Uma string com data e hora conforme especificao [RFC-3339](https://datatracker.ietf.org/doc/html/rfc3339), sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Format: date-time
	ExpirationDateTime strfmt.DateTime `json:"expirationDateTime,omitempty" yaml:"expirationDateTime,omitempty"`

	// logged user
	// Required: true
	LoggedUser *OpenbankingBrasilAutomaticPaymentV1LoggedUser `json:"loggedUser" yaml:"loggedUser"`

	// Campo destinado a configurao dos diferentes produtos de pagamentos recorrentes.
	// Required: true
	RecurringConfiguration interface{} `json:"recurringConfiguration" yaml:"recurringConfiguration"`

	// Identificador nico do consentimento de longa durao criado para a iniciao de pagamento solicitada. Dever ser um URN - Uniform Resource Name. Um URN, conforme definido na [RFC8141](https://datatracker.ietf.org/doc/html/rfc8141)  um Uniform Resource Identifier - URI - que  atribudo sob o URI scheme "urn" e um namespace URN especfico, com a inteno de que o URN seja um identificador de recurso persistente e independente da localizao.
	// Considerando a string urn:bancoex:C1DD33123 como exemplo para `recurringConsentId` temos:
	// o namespace(urn)
	// o identificador associado ao namespace da instituio transmissora (bancoex)
	// o identificador especfico dentro do namespace (C1DD33123). Informaes mais detalhadas sobre a construo de namespaces devem ser consultadas na [RFC8141](https://datatracker.ietf.org/doc/html/rfc8141).
	// Required: true
	// Max Length: 256
	// Pattern: ^urn:[a-zA-Z0-9][a-zA-Z0-9\-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$
	RecurringConsentID *string `json:"recurringConsentId" yaml:"recurringConsentId"`

	// rejection
	Rejection *OpenbankingBrasilAutomaticPaymentV1Rejection `json:"rejection,omitempty" yaml:"rejection,omitempty"`

	// revocation
	Revocation *OpenbankingBrasilAutomaticPaymentV1Revocation1 `json:"revocation,omitempty" yaml:"revocation,omitempty"`

	// risk signals
	RiskSignals *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents `json:"riskSignals,omitempty" yaml:"riskSignals,omitempty"`

	// Data e hora em que o consentimento deve passar a ser vlido. Uma string com data e hora conforme especificao [RFC-3339](https://datatracker.ietf.org/doc/html/rfc3339), sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	StartDateTime *strfmt.DateTime `json:"startDateTime" yaml:"startDateTime"`

	// status
	// Required: true
	Status *OpenbankingBrasilAutomaticPaymentV1EnumAuthorisationStatusType `json:"status" yaml:"status"`

	// Data e hora em que o consentimento teve o status atualizado. Uma string com data e hora conforme especificao [RFC-3339](https://datatracker.ietf.org/doc/html/rfc3339), sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime" yaml:"statusUpdateDateTime"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 IntrospectResponse
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.IntrospectResponse = aO0

	// AO1
	var dataAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		AdditionalInformation string `json:"additionalInformation,omitempty"`

		BusinessEntity *OpenbankingBrasilAutomaticPaymentV1BusinessEntity `json:"businessEntity,omitempty"`

		CreationDateTime *strfmt.DateTime `json:"creationDateTime"`

		Creditors []*OpenbankingBrasilAutomaticPaymentV1Creditor `json:"creditors"`

		DebtorAccount *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount `json:"debtorAccount,omitempty"`

		ExpirationDateTime strfmt.DateTime `json:"expirationDateTime,omitempty"`

		LoggedUser *OpenbankingBrasilAutomaticPaymentV1LoggedUser `json:"loggedUser"`

		RecurringConfiguration interface{} `json:"recurringConfiguration"`

		RecurringConsentID *string `json:"recurringConsentId"`

		Rejection *OpenbankingBrasilAutomaticPaymentV1Rejection `json:"rejection,omitempty"`

		Revocation *OpenbankingBrasilAutomaticPaymentV1Revocation1 `json:"revocation,omitempty"`

		RiskSignals *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents `json:"riskSignals,omitempty"`

		StartDateTime *strfmt.DateTime `json:"startDateTime"`

		Status *OpenbankingBrasilAutomaticPaymentV1EnumAuthorisationStatusType `json:"status"`

		StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.AccountIDs = dataAO1.AccountIDs

	m.AdditionalInformation = dataAO1.AdditionalInformation

	m.BusinessEntity = dataAO1.BusinessEntity

	m.CreationDateTime = dataAO1.CreationDateTime

	m.Creditors = dataAO1.Creditors

	m.DebtorAccount = dataAO1.DebtorAccount

	m.ExpirationDateTime = dataAO1.ExpirationDateTime

	m.LoggedUser = dataAO1.LoggedUser

	m.RecurringConfiguration = dataAO1.RecurringConfiguration

	m.RecurringConsentID = dataAO1.RecurringConsentID

	m.Rejection = dataAO1.Rejection

	m.Revocation = dataAO1.Revocation

	m.RiskSignals = dataAO1.RiskSignals

	m.StartDateTime = dataAO1.StartDateTime

	m.Status = dataAO1.Status

	m.StatusUpdateDateTime = dataAO1.StatusUpdateDateTime

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		AdditionalInformation string `json:"additionalInformation,omitempty"`

		BusinessEntity *OpenbankingBrasilAutomaticPaymentV1BusinessEntity `json:"businessEntity,omitempty"`

		CreationDateTime *strfmt.DateTime `json:"creationDateTime"`

		Creditors []*OpenbankingBrasilAutomaticPaymentV1Creditor `json:"creditors"`

		DebtorAccount *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount `json:"debtorAccount,omitempty"`

		ExpirationDateTime strfmt.DateTime `json:"expirationDateTime,omitempty"`

		LoggedUser *OpenbankingBrasilAutomaticPaymentV1LoggedUser `json:"loggedUser"`

		RecurringConfiguration interface{} `json:"recurringConfiguration"`

		RecurringConsentID *string `json:"recurringConsentId"`

		Rejection *OpenbankingBrasilAutomaticPaymentV1Rejection `json:"rejection,omitempty"`

		Revocation *OpenbankingBrasilAutomaticPaymentV1Revocation1 `json:"revocation,omitempty"`

		RiskSignals *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents `json:"riskSignals,omitempty"`

		StartDateTime *strfmt.DateTime `json:"startDateTime"`

		Status *OpenbankingBrasilAutomaticPaymentV1EnumAuthorisationStatusType `json:"status"`

		StatusUpdateDateTime *strfmt.DateTime `json:"statusUpdateDateTime"`
	}

	dataAO1.AccountIDs = m.AccountIDs

	dataAO1.AdditionalInformation = m.AdditionalInformation

	dataAO1.BusinessEntity = m.BusinessEntity

	dataAO1.CreationDateTime = m.CreationDateTime

	dataAO1.Creditors = m.Creditors

	dataAO1.DebtorAccount = m.DebtorAccount

	dataAO1.ExpirationDateTime = m.ExpirationDateTime

	dataAO1.LoggedUser = m.LoggedUser

	dataAO1.RecurringConfiguration = m.RecurringConfiguration

	dataAO1.RecurringConsentID = m.RecurringConsentID

	dataAO1.Rejection = m.Rejection

	dataAO1.Revocation = m.Revocation

	dataAO1.RiskSignals = m.RiskSignals

	dataAO1.StartDateTime = m.StartDateTime

	dataAO1.Status = m.Status

	dataAO1.StatusUpdateDateTime = m.StatusUpdateDateTime

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this introspect o b b r automatic payments recurring consent response
func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with IntrospectResponse
	if err := m.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAdditionalInformation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBusinessEntity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDebtorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpirationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLoggedUser(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecurringConfiguration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecurringConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRejection(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevocation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRiskSignals(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartDateTime(formats); err != nil {
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

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateAdditionalInformation(formats strfmt.Registry) error {

	if swag.IsZero(m.AdditionalInformation) { // not required
		return nil
	}

	if err := validate.MaxLength("additionalInformation", "body", m.AdditionalInformation, 140); err != nil {
		return err
	}

	if err := validate.Pattern("additionalInformation", "body", m.AdditionalInformation, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateBusinessEntity(formats strfmt.Registry) error {

	if swag.IsZero(m.BusinessEntity) { // not required
		return nil
	}

	if m.BusinessEntity != nil {
		if err := m.BusinessEntity.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("businessEntity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("businessEntity")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateCreationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("creationDateTime", "body", m.CreationDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("creationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateCreditors(formats strfmt.Registry) error {

	if err := validate.Required("creditors", "body", m.Creditors); err != nil {
		return err
	}

	iCreditorsSize := int64(len(m.Creditors))

	if err := validate.MinItems("creditors", "body", iCreditorsSize, 1); err != nil {
		return err
	}

	for i := 0; i < len(m.Creditors); i++ {
		if swag.IsZero(m.Creditors[i]) { // not required
			continue
		}

		if m.Creditors[i] != nil {
			if err := m.Creditors[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("creditors" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("creditors" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateDebtorAccount(formats strfmt.Registry) error {

	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if m.DebtorAccount != nil {
		if err := m.DebtorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("debtorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("debtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateExpirationDateTime(formats strfmt.Registry) error {

	if swag.IsZero(m.ExpirationDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("expirationDateTime", "body", "date-time", m.ExpirationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateLoggedUser(formats strfmt.Registry) error {

	if err := validate.Required("loggedUser", "body", m.LoggedUser); err != nil {
		return err
	}

	if m.LoggedUser != nil {
		if err := m.LoggedUser.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("loggedUser")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("loggedUser")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateRecurringConfiguration(formats strfmt.Registry) error {

	if m.RecurringConfiguration == nil {
		return errors.Required("recurringConfiguration", "body", nil)
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateRecurringConsentID(formats strfmt.Registry) error {

	if err := validate.Required("recurringConsentId", "body", m.RecurringConsentID); err != nil {
		return err
	}

	if err := validate.MaxLength("recurringConsentId", "body", *m.RecurringConsentID, 256); err != nil {
		return err
	}

	if err := validate.Pattern("recurringConsentId", "body", *m.RecurringConsentID, `^urn:[a-zA-Z0-9][a-zA-Z0-9\-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$`); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateRejection(formats strfmt.Registry) error {

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

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateRevocation(formats strfmt.Registry) error {

	if swag.IsZero(m.Revocation) { // not required
		return nil
	}

	if m.Revocation != nil {
		if err := m.Revocation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revocation")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateRiskSignals(formats strfmt.Registry) error {

	if swag.IsZero(m.RiskSignals) { // not required
		return nil
	}

	if m.RiskSignals != nil {
		if err := m.RiskSignals.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("riskSignals")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("riskSignals")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateStartDateTime(formats strfmt.Registry) error {

	if err := validate.Required("startDateTime", "body", m.StartDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("startDateTime", "body", "date-time", m.StartDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateStatus(formats strfmt.Registry) error {

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

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) validateStatusUpdateDateTime(formats strfmt.Registry) error {

	if err := validate.Required("statusUpdateDateTime", "body", m.StatusUpdateDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("statusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this introspect o b b r automatic payments recurring consent response based on the context it is used
func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with IntrospectResponse
	if err := m.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBusinessEntity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditors(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLoggedUser(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRejection(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRevocation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRiskSignals(ctx, formats); err != nil {
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

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateBusinessEntity(ctx context.Context, formats strfmt.Registry) error {

	if m.BusinessEntity != nil {

		if swag.IsZero(m.BusinessEntity) { // not required
			return nil
		}

		if err := m.BusinessEntity.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("businessEntity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("businessEntity")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateCreditors(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Creditors); i++ {

		if m.Creditors[i] != nil {

			if swag.IsZero(m.Creditors[i]) { // not required
				return nil
			}

			if err := m.Creditors[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("creditors" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("creditors" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.DebtorAccount != nil {

		if swag.IsZero(m.DebtorAccount) { // not required
			return nil
		}

		if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("debtorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("debtorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateLoggedUser(ctx context.Context, formats strfmt.Registry) error {

	if m.LoggedUser != nil {

		if err := m.LoggedUser.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("loggedUser")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("loggedUser")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateRejection(ctx context.Context, formats strfmt.Registry) error {

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

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateRevocation(ctx context.Context, formats strfmt.Registry) error {

	if m.Revocation != nil {

		if swag.IsZero(m.Revocation) { // not required
			return nil
		}

		if err := m.Revocation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("revocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("revocation")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateRiskSignals(ctx context.Context, formats strfmt.Registry) error {

	if m.RiskSignals != nil {

		if swag.IsZero(m.RiskSignals) { // not required
			return nil
		}

		if err := m.RiskSignals.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("riskSignals")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("riskSignals")
			}
			return err
		}
	}

	return nil
}

func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) contextValidateStatus(ctx context.Context, formats strfmt.Registry) error {

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
func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IntrospectOBBRAutomaticPaymentsRecurringConsentResponse) UnmarshalBinary(b []byte) error {
	var res IntrospectOBBRAutomaticPaymentsRecurringConsentResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
