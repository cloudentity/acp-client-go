// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DCRDetails d c r details
//
// swagger:model DCRDetails
type DCRDetails struct {

	// certificate bound access token
	CertificateBoundAccessToken bool `json:"certificate_bound_access_token,omitempty"`

	// client id
	ClientID string `json:"client_id,omitempty"`

	// client name
	ClientName string `json:"client_name,omitempty"`

	// grant types
	GrantTypes []string `json:"grant_types"`

	// scopes
	Scopes []string `json:"scopes"`

	// software statement provided
	SoftwareStatementProvided bool `json:"software_statement_provided,omitempty"`

	// token endpoint auth method
	// Enum: [client_secret_basic client_secret_post client_secret_jwt private_key_jwt self_signed_tls_client_auth tls_client_auth none]
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

// Validate validates this d c r details
func (m *DCRDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGrantTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpointAuthMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var dCRDetailsGrantTypesItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authorization_code","implicit","client_credentials","refresh_token","password","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:openid:params:grant-type:ciba","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		dCRDetailsGrantTypesItemsEnum = append(dCRDetailsGrantTypesItemsEnum, v)
	}
}

func (m *DCRDetails) validateGrantTypesItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, dCRDetailsGrantTypesItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *DCRDetails) validateGrantTypes(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantTypes) { // not required
		return nil
	}

	for i := 0; i < len(m.GrantTypes); i++ {

		// value enum
		if err := m.validateGrantTypesItemsEnum("grant_types"+"."+strconv.Itoa(i), "body", m.GrantTypes[i]); err != nil {
			return err
		}

	}

	return nil
}

var dCRDetailsTypeTokenEndpointAuthMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		dCRDetailsTypeTokenEndpointAuthMethodPropEnum = append(dCRDetailsTypeTokenEndpointAuthMethodPropEnum, v)
	}
}

const (

	// DCRDetailsTokenEndpointAuthMethodClientSecretBasic captures enum value "client_secret_basic"
	DCRDetailsTokenEndpointAuthMethodClientSecretBasic string = "client_secret_basic"

	// DCRDetailsTokenEndpointAuthMethodClientSecretPost captures enum value "client_secret_post"
	DCRDetailsTokenEndpointAuthMethodClientSecretPost string = "client_secret_post"

	// DCRDetailsTokenEndpointAuthMethodClientSecretJwt captures enum value "client_secret_jwt"
	DCRDetailsTokenEndpointAuthMethodClientSecretJwt string = "client_secret_jwt"

	// DCRDetailsTokenEndpointAuthMethodPrivateKeyJwt captures enum value "private_key_jwt"
	DCRDetailsTokenEndpointAuthMethodPrivateKeyJwt string = "private_key_jwt"

	// DCRDetailsTokenEndpointAuthMethodSelfSignedTLSClientAuth captures enum value "self_signed_tls_client_auth"
	DCRDetailsTokenEndpointAuthMethodSelfSignedTLSClientAuth string = "self_signed_tls_client_auth"

	// DCRDetailsTokenEndpointAuthMethodTLSClientAuth captures enum value "tls_client_auth"
	DCRDetailsTokenEndpointAuthMethodTLSClientAuth string = "tls_client_auth"

	// DCRDetailsTokenEndpointAuthMethodNone captures enum value "none"
	DCRDetailsTokenEndpointAuthMethodNone string = "none"
)

// prop value enum
func (m *DCRDetails) validateTokenEndpointAuthMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, dCRDetailsTypeTokenEndpointAuthMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *DCRDetails) validateTokenEndpointAuthMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateTokenEndpointAuthMethodEnum("token_endpoint_auth_method", "body", m.TokenEndpointAuthMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this d c r details based on context it is used
func (m *DCRDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DCRDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DCRDetails) UnmarshalBinary(b []byte) error {
	var res DCRDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}