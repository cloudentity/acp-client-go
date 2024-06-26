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

// OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents RiskSignalsConsents
//
// # Sinais de risco para iniciao de pagamentos automticos
//
// [Restrio] Deve ser enviado quando o consentimento for para o produto Pix Automtico (O objeto "/data/recurringConfiguration/automatic" usado no oneOf). S estar presente aps a primeira edio do consentimento de longa durao.
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents
type OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents struct {

	// Data de cadastro do cliente na iniciadora.
	// Required: true
	// Format: date
	AccountTenure strfmt.Date `json:"accountTenure" yaml:"accountTenure"`

	// Indica em qual antena o dispositivo est conectado.
	AntennaInformation string `json:"antennaInformation,omitempty" yaml:"antennaInformation,omitempty"`

	// ID nico do dispositivo gerado pela plataforma.
	// Example: 00000000-54b3-e7c7-0000-000046bffd97
	// Required: true
	DeviceID string `json:"deviceId" yaml:"deviceId"`

	// Indica por quanto tempo (em milissegundos) o dispositivo est ligado.
	// Required: true
	ElapsedTimeSinceBoot int64 `json:"elapsedTimeSinceBoot" yaml:"elapsedTimeSinceBoot"`

	// geolocation
	Geolocation *OpenbankingBrasilAutomaticPaymentV1Geolocation `json:"geolocation,omitempty" yaml:"geolocation,omitempty"`

	// integrity
	Integrity *OpenbankingBrasilAutomaticPaymentV1Integrity `json:"integrity,omitempty" yaml:"integrity,omitempty"`

	// Indica chamada ativa no momento do vnculo.
	//
	// [Restrio] Caso o sinal de risco esteja disponvel (cliente permitiu que fosse coletado), o mesmo dever ser enviado
	IsCallInProgress bool `json:"isCallInProgress,omitempty" yaml:"isCallInProgress,omitempty"`

	// Indica se a bateria do dispositivo est sendo carregada.
	IsCharging bool `json:"isCharging,omitempty" yaml:"isCharging,omitempty"`

	// Indica se o dispositivo est em modo de desenvolvedor.
	IsDevModeEnabled bool `json:"isDevModeEnabled,omitempty" yaml:"isDevModeEnabled,omitempty"`

	// Indica se o dispositivo  emulado ou real.
	IsEmulated bool `json:"isEmulated,omitempty" yaml:"isEmulated,omitempty"`

	// Indica se o dispositivo est usando um GPS falso.
	IsMockGPS bool `json:"isMockGPS,omitempty" yaml:"isMockGPS,omitempty"`

	// Indica o uso do MonkeyRunner.
	IsMonkeyRunner bool `json:"isMonkeyRunner,omitempty" yaml:"isMonkeyRunner,omitempty"`

	// Indica se o dispositivo atualmente est com permisso de root.
	// Example: false
	// Required: true
	IsRootedDevice bool `json:"isRootedDevice" yaml:"isRootedDevice"`

	// Indica se o dispositivo est conectado a outro dispositivo via USB.
	IsUsbConnected bool `json:"isUsbConnected,omitempty" yaml:"isUsbConnected,omitempty"`

	// Indica o idioma do dispositivo no formato ISO 639-1.
	// Required: true
	Language string `json:"language" yaml:"language"`

	// Verso do sistema operacional.
	// Required: true
	OsVersion string `json:"osVersion" yaml:"osVersion"`

	// Indica o nvel de brilho da tela do dispositivo.
	// Em dispositivos Android o valor  um inteiro, entre 0 e 255, inclusive;
	// Em dispositivos iOS o valor  um ponto flutuante entre 0.0 e 1.0.
	// Required: true
	ScreenBrightness float64 `json:"screenBrightness" yaml:"screenBrightness"`

	// screen dimensions
	// Required: true
	ScreenDimensions *OpenbankingBrasilAutomaticPaymentV1ScreenDimensions `json:"screenDimensions" yaml:"screenDimensions"`

	// Indica a configurao de fuso horrio do dispositivo do usurio, com o formato UTC offset: hh[:mm]
	// Required: true
	UserTimeZoneOffset string `json:"userTimeZoneOffset" yaml:"userTimeZoneOffset"`
}

// Validate validates this openbanking brasil automatic payment v1 risk signals consents
func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountTenure(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateElapsedTimeSinceBoot(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGeolocation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntegrity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsRootedDevice(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLanguage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOsVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScreenBrightness(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScreenDimensions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserTimeZoneOffset(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateAccountTenure(formats strfmt.Registry) error {

	if err := validate.Required("accountTenure", "body", strfmt.Date(m.AccountTenure)); err != nil {
		return err
	}

	if err := validate.FormatOf("accountTenure", "body", "date", m.AccountTenure.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateDeviceID(formats strfmt.Registry) error {

	if err := validate.RequiredString("deviceId", "body", m.DeviceID); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateElapsedTimeSinceBoot(formats strfmt.Registry) error {

	if err := validate.Required("elapsedTimeSinceBoot", "body", int64(m.ElapsedTimeSinceBoot)); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateGeolocation(formats strfmt.Registry) error {
	if swag.IsZero(m.Geolocation) { // not required
		return nil
	}

	if m.Geolocation != nil {
		if err := m.Geolocation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("geolocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("geolocation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateIntegrity(formats strfmt.Registry) error {
	if swag.IsZero(m.Integrity) { // not required
		return nil
	}

	if m.Integrity != nil {
		if err := m.Integrity.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("integrity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("integrity")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateIsRootedDevice(formats strfmt.Registry) error {

	if err := validate.Required("isRootedDevice", "body", bool(m.IsRootedDevice)); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateLanguage(formats strfmt.Registry) error {

	if err := validate.RequiredString("language", "body", m.Language); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateOsVersion(formats strfmt.Registry) error {

	if err := validate.RequiredString("osVersion", "body", m.OsVersion); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateScreenBrightness(formats strfmt.Registry) error {

	if err := validate.Required("screenBrightness", "body", float64(m.ScreenBrightness)); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateScreenDimensions(formats strfmt.Registry) error {

	if err := validate.Required("screenDimensions", "body", m.ScreenDimensions); err != nil {
		return err
	}

	if m.ScreenDimensions != nil {
		if err := m.ScreenDimensions.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("screenDimensions")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("screenDimensions")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) validateUserTimeZoneOffset(formats strfmt.Registry) error {

	if err := validate.RequiredString("userTimeZoneOffset", "body", m.UserTimeZoneOffset); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil automatic payment v1 risk signals consents based on the context it is used
func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGeolocation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIntegrity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScreenDimensions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) contextValidateGeolocation(ctx context.Context, formats strfmt.Registry) error {

	if m.Geolocation != nil {

		if swag.IsZero(m.Geolocation) { // not required
			return nil
		}

		if err := m.Geolocation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("geolocation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("geolocation")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) contextValidateIntegrity(ctx context.Context, formats strfmt.Registry) error {

	if m.Integrity != nil {

		if swag.IsZero(m.Integrity) { // not required
			return nil
		}

		if err := m.Integrity.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("integrity")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("integrity")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) contextValidateScreenDimensions(ctx context.Context, formats strfmt.Registry) error {

	if m.ScreenDimensions != nil {

		if err := m.ScreenDimensions.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("screenDimensions")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("screenDimensions")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilAutomaticPaymentV1RiskSignalsConsents
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
