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

// OpenbankingBrasilPaymentV4Data2 OpenbankingBrasilPaymentV4Data2 Data2
//
// Objeto contendo as informaes de resposta do consentimento para a iniciao de pagamento individual.
//
// swagger:model OpenbankingBrasilPaymentV4Data2
type OpenbankingBrasilPaymentV4Data2 struct {

	// business entity
	BusinessEntity *OpenbankingBrasilPaymentV4BusinessEntity `json:"businessEntity,omitempty" yaml:"businessEntity,omitempty"`

	// Identificador nico do consentimento criado para a iniciao de pagamento solicitada. Dever ser um URN - Uniform Resource Name.
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
	// Pattern: ^urn:[a-zA-Z0-9][a-zA-Z0-9\-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$
	ConsentID string `json:"consentId" yaml:"consentId"`

	// Data e hora em que o consentimento foi criado. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	CreationDateTime strfmt.DateTime `json:"creationDateTime" yaml:"creationDateTime"`

	// creditor
	// Required: true
	Creditor *OpenbankingBrasilPaymentV4Identification `json:"creditor" yaml:"creditor"`

	// debtor account
	DebtorAccount *OpenbankingBrasilPaymentV4ConsentsDebtorAccount `json:"debtorAccount,omitempty" yaml:"debtorAccount,omitempty"`

	// Data e hora em que o consentimento da iniciao de pagamento expira, devendo ser sempre o creationDateTime mais 5 minutos. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC (UTC time format).
	// O consentimento  criado com o status AWAITING_AUTHORISATION, e deve assumir o status AUTHORIZED ou REJECTED antes do tempo de expirao - 5 minutos. Caso o tempo seja expirado, o status deve assumir REJECTED.
	// Para o cenrio em que o status assumiu AUTHORISED, o tempo mximo do expirationDateTime do consentimento deve assumir "now + 60 minutos". Este  o tempo para consumir o consentimento autorizado, mudando seu status para CONSUMED. No  possvel prorrogar este tempo e a criao de um novo consentimento ser necessria para os cenrios de insucesso.
	// O tempo do expirationDateTime  garantido com os 15 minutos do access token, sendo possvel utilizar mais trs refresh tokens at totalizar 60 minutos.
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	ExpirationDateTime strfmt.DateTime `json:"expirationDateTime" yaml:"expirationDateTime"`

	// logged user
	// Required: true
	LoggedUser *OpenbankingBrasilPaymentV4LoggedUser `json:"loggedUser" yaml:"loggedUser"`

	// payment
	// Required: true
	Payment *OpenbankingBrasilPaymentV4PaymentConsent `json:"payment" yaml:"payment"`

	// rejection reason
	RejectionReason *OpenbankingBrasilPaymentV4ConsentRejectionReason `json:"rejectionReason,omitempty" yaml:"rejectionReason,omitempty"`

	// status
	// Required: true
	Status *OpenbankingBrasilPaymentV4EnumAuthorisationStatusType `json:"status" yaml:"status"`

	// Data e hora em que o recurso foi atualizado. Uma string com data e hora conforme especificao RFC-3339, sempre com a utilizao de timezone UTC(UTC time format).
	// Example: 2021-05-21T08:30:00Z
	// Required: true
	// Format: date-time
	StatusUpdateDateTime strfmt.DateTime `json:"statusUpdateDateTime" yaml:"statusUpdateDateTime"`
}

// Validate validates this openbanking brasil payment v4 data2
func (m *OpenbankingBrasilPaymentV4Data2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBusinessEntity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConsentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreditor(formats); err != nil {
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

	if err := m.validatePayment(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRejectionReason(formats); err != nil {
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

func (m *OpenbankingBrasilPaymentV4Data2) validateBusinessEntity(formats strfmt.Registry) error {
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

func (m *OpenbankingBrasilPaymentV4Data2) validateConsentID(formats strfmt.Registry) error {

	if err := validate.RequiredString("consentId", "body", m.ConsentID); err != nil {
		return err
	}

	if err := validate.MaxLength("consentId", "body", m.ConsentID, 256); err != nil {
		return err
	}

	if err := validate.Pattern("consentId", "body", m.ConsentID, `^urn:[a-zA-Z0-9][a-zA-Z0-9\-]{0,31}:[a-zA-Z0-9()+,\-.:=@;$_!*'%\/?#]+$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateCreationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("creationDateTime", "body", strfmt.DateTime(m.CreationDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("creationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateCreditor(formats strfmt.Registry) error {

	if err := validate.Required("creditor", "body", m.Creditor); err != nil {
		return err
	}

	if m.Creditor != nil {
		if err := m.Creditor.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("creditor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("creditor")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateDebtorAccount(formats strfmt.Registry) error {
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

func (m *OpenbankingBrasilPaymentV4Data2) validateExpirationDateTime(formats strfmt.Registry) error {

	if err := validate.Required("expirationDateTime", "body", strfmt.DateTime(m.ExpirationDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("expirationDateTime", "body", "date-time", m.ExpirationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateLoggedUser(formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4Data2) validatePayment(formats strfmt.Registry) error {

	if err := validate.Required("payment", "body", m.Payment); err != nil {
		return err
	}

	if m.Payment != nil {
		if err := m.Payment.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payment")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payment")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateRejectionReason(formats strfmt.Registry) error {
	if swag.IsZero(m.RejectionReason) { // not required
		return nil
	}

	if m.RejectionReason != nil {
		if err := m.RejectionReason.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rejectionReason")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rejectionReason")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) validateStatus(formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4Data2) validateStatusUpdateDateTime(formats strfmt.Registry) error {

	if err := validate.Required("statusUpdateDateTime", "body", strfmt.DateTime(m.StatusUpdateDateTime)); err != nil {
		return err
	}

	if err := validate.FormatOf("statusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil payment v4 data2 based on the context it is used
func (m *OpenbankingBrasilPaymentV4Data2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBusinessEntity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreditor(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLoggedUser(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePayment(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRejectionReason(ctx, formats); err != nil {
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

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateBusinessEntity(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateCreditor(ctx context.Context, formats strfmt.Registry) error {

	if m.Creditor != nil {

		if err := m.Creditor.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("creditor")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("creditor")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateLoggedUser(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4Data2) contextValidatePayment(ctx context.Context, formats strfmt.Registry) error {

	if m.Payment != nil {

		if err := m.Payment.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payment")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payment")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateRejectionReason(ctx context.Context, formats strfmt.Registry) error {

	if m.RejectionReason != nil {

		if swag.IsZero(m.RejectionReason) { // not required
			return nil
		}

		if err := m.RejectionReason.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rejectionReason")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rejectionReason")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4Data2) contextValidateStatus(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OpenbankingBrasilPaymentV4Data2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4Data2) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV4Data2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
