// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OpenbankingDomesticPaymentConsentWithClient openbanking domestic payment consent with client
//
// swagger:model OpenbankingDomesticPaymentConsentWithClient
type OpenbankingDomesticPaymentConsentWithClient struct {

	// authorisation
	Authorisation *DomesticPaymentConsentAuthorisation `json:"Authorisation,omitempty"`

	// url to a client website
	// Example: https://example.com
	ClientURI string `json:"client_uri,omitempty"`

	// Unique identification as assigned to identify the domestic payment resource.
	ConsentID string `json:"consent_id,omitempty"`

	// Date and time at which the resource was created.
	// Format: date-time
	CreationDateTime strfmt.DateTime `json:"CreationDateTime,omitempty"`

	// delivery address
	DeliveryAddress *RiskDeliveryAddress `json:"DeliveryAddress,omitempty"`

	// client id
	// Example: default
	ID string `json:"id,omitempty"`

	// initiation
	Initiation *DomesticPaymentConsentDataInitiation `json:"Initiation,omitempty"`

	// url to a page where client logo is served
	// Example: https://example.com/logo.png
	LogoURI string `json:"logo_uri,omitempty"`

	// Category code conform to ISO 18245, related to the type of services or goods the merchant provides for the transaction.
	// Max Length: 4
	// Min Length: 3
	MerchantCategoryCode string `json:"MerchantCategoryCode,omitempty"`

	// The unique customer identifier of the PSU with the merchant.
	// Max Length: 70
	// Min Length: 1
	MerchantCustomerIdentification string `json:"MerchantCustomerIdentification,omitempty"`

	// client name
	// Example: My app
	Name string `json:"name,omitempty"`

	// Specifies the payment context
	// Enum: [[BillPayment EcommerceGoods EcommerceServices Other PartyToParty]]
	PaymentContextCode string `json:"PaymentContextCode,omitempty"`

	// Specifies to share the refund account details with PISP
	// Enum: [[No Yes]]
	ReadRefundAccount string `json:"ReadRefundAccount,omitempty"`

	// s c a support data
	SCASupportData *DomesticPaymentConsentSCASupportData `json:"SCASupportData,omitempty"`

	// Specifies the status of consent resource in code form.
	Status string `json:"Status,omitempty"`

	// Date and time at which the resource status was updated.
	// Format: date-time
	StatusUpdateDateTime strfmt.DateTime `json:"StatusUpdateDateTime,omitempty"`
}

// Validate validates this openbanking domestic payment consent with client
func (m *OpenbankingDomesticPaymentConsentWithClient) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeliveryAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInitiation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMerchantCategoryCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMerchantCustomerIdentification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentContextCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReadRefundAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSCASupportData(formats); err != nil {
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

func (m *OpenbankingDomesticPaymentConsentWithClient) validateAuthorisation(formats strfmt.Registry) error {
	if swag.IsZero(m.Authorisation) { // not required
		return nil
	}

	if m.Authorisation != nil {
		if err := m.Authorisation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateCreationDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreationDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreationDateTime", "body", "date-time", m.CreationDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateDeliveryAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.DeliveryAddress) { // not required
		return nil
	}

	if m.DeliveryAddress != nil {
		if err := m.DeliveryAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DeliveryAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateInitiation(formats strfmt.Registry) error {
	if swag.IsZero(m.Initiation) { // not required
		return nil
	}

	if m.Initiation != nil {
		if err := m.Initiation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateMerchantCategoryCode(formats strfmt.Registry) error {
	if swag.IsZero(m.MerchantCategoryCode) { // not required
		return nil
	}

	if err := validate.MinLength("MerchantCategoryCode", "body", m.MerchantCategoryCode, 3); err != nil {
		return err
	}

	if err := validate.MaxLength("MerchantCategoryCode", "body", m.MerchantCategoryCode, 4); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateMerchantCustomerIdentification(formats strfmt.Registry) error {
	if swag.IsZero(m.MerchantCustomerIdentification) { // not required
		return nil
	}

	if err := validate.MinLength("MerchantCustomerIdentification", "body", m.MerchantCustomerIdentification, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("MerchantCustomerIdentification", "body", m.MerchantCustomerIdentification, 70); err != nil {
		return err
	}

	return nil
}

var openbankingDomesticPaymentConsentWithClientTypePaymentContextCodePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["[BillPayment EcommerceGoods EcommerceServices Other PartyToParty]"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		openbankingDomesticPaymentConsentWithClientTypePaymentContextCodePropEnum = append(openbankingDomesticPaymentConsentWithClientTypePaymentContextCodePropEnum, v)
	}
}

const (

	// OpenbankingDomesticPaymentConsentWithClientPaymentContextCodeBillPaymentEcommerceGoodsEcommerceServicesOtherPartyToParty captures enum value "[BillPayment EcommerceGoods EcommerceServices Other PartyToParty]"
	OpenbankingDomesticPaymentConsentWithClientPaymentContextCodeBillPaymentEcommerceGoodsEcommerceServicesOtherPartyToParty string = "[BillPayment EcommerceGoods EcommerceServices Other PartyToParty]"
)

// prop value enum
func (m *OpenbankingDomesticPaymentConsentWithClient) validatePaymentContextCodeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, openbankingDomesticPaymentConsentWithClientTypePaymentContextCodePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validatePaymentContextCode(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentContextCode) { // not required
		return nil
	}

	// value enum
	if err := m.validatePaymentContextCodeEnum("PaymentContextCode", "body", m.PaymentContextCode); err != nil {
		return err
	}

	return nil
}

var openbankingDomesticPaymentConsentWithClientTypeReadRefundAccountPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["[No Yes]"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		openbankingDomesticPaymentConsentWithClientTypeReadRefundAccountPropEnum = append(openbankingDomesticPaymentConsentWithClientTypeReadRefundAccountPropEnum, v)
	}
}

const (

	// OpenbankingDomesticPaymentConsentWithClientReadRefundAccountNoYes captures enum value "[No Yes]"
	OpenbankingDomesticPaymentConsentWithClientReadRefundAccountNoYes string = "[No Yes]"
)

// prop value enum
func (m *OpenbankingDomesticPaymentConsentWithClient) validateReadRefundAccountEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, openbankingDomesticPaymentConsentWithClientTypeReadRefundAccountPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateReadRefundAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.ReadRefundAccount) { // not required
		return nil
	}

	// value enum
	if err := m.validateReadRefundAccountEnum("ReadRefundAccount", "body", m.ReadRefundAccount); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateSCASupportData(formats strfmt.Registry) error {
	if swag.IsZero(m.SCASupportData) { // not required
		return nil
	}

	if m.SCASupportData != nil {
		if err := m.SCASupportData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) validateStatusUpdateDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.StatusUpdateDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("StatusUpdateDateTime", "body", "date-time", m.StatusUpdateDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking domestic payment consent with client based on the context it is used
func (m *OpenbankingDomesticPaymentConsentWithClient) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthorisation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDeliveryAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInitiation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSCASupportData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) contextValidateAuthorisation(ctx context.Context, formats strfmt.Registry) error {

	if m.Authorisation != nil {
		if err := m.Authorisation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Authorisation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) contextValidateDeliveryAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.DeliveryAddress != nil {
		if err := m.DeliveryAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DeliveryAddress")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) contextValidateInitiation(ctx context.Context, formats strfmt.Registry) error {

	if m.Initiation != nil {
		if err := m.Initiation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Initiation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingDomesticPaymentConsentWithClient) contextValidateSCASupportData(ctx context.Context, formats strfmt.Registry) error {

	if m.SCASupportData != nil {
		if err := m.SCASupportData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SCASupportData")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingDomesticPaymentConsentWithClient) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingDomesticPaymentConsentWithClient) UnmarshalBinary(b []byte) error {
	var res OpenbankingDomesticPaymentConsentWithClient
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
