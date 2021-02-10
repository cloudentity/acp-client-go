// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SAMLAuthentication s a m l authentication
//
// swagger:model SAMLAuthentication
type SAMLAuthentication struct {

	// unique id of a service provider, if not provided will be generated
	// Example: https://localhost:8443/default/default/login
	EntityIssuer string `json:"entity_issuer,omitempty"`

	// attribute name from AttributeStatement saml response which will be used as identifier in ACP
	// applies only when identifier source is set to attribute
	IdentifierAttribute string `json:"identifier_attribute,omitempty"`

	// identifier source, one of: subject | attribute
	IdentifierSource string `json:"identifier_source,omitempty"`

	// idp certificate, must start with -----BEGIN CERTIFICATE----- and end with -----END CERTIFICATE-----
	IdpCertificate string `json:"idp_certificate,omitempty"`

	// endpoint where IDP will post SamlResponse
	// Example: https://localhost:8443/default/default/login
	RedirectURL string `json:"redirect_url,omitempty"`

	// endpoint where SamlRequest will be sent
	// Example: https://test-dev-ed.my.salesforce.com/idp/endpoint/HttpPost
	SSOURL string `json:"sso_url,omitempty"`

	// name id format of saml subject
	// applies only when identifier source is set to subject
	// allowed values:
	// urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
	// urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
	// urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
	// urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
	// urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted
	// urn:oasis:names:tc:SAML:2.0:nameid-format:entity
	// urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos
	// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
	// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
	// default value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
	SubjectNameIDFormat string `json:"subject_name_id_format,omitempty"`
}

// Validate validates this s a m l authentication
func (m *SAMLAuthentication) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this s a m l authentication based on context it is used
func (m *SAMLAuthentication) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SAMLAuthentication) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SAMLAuthentication) UnmarshalBinary(b []byte) error {
	var res SAMLAuthentication
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
