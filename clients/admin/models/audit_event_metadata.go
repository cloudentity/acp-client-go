// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// AuditEventMetadata audit event metadata
//
// swagger:model AuditEventMetadata
type AuditEventMetadata struct {

	// Access request actor claims.
	//
	// It's only populated if the token has been issued in token exchange delegation flow.
	ActorClaims map[string]interface{} `json:"actor_claims,omitempty" yaml:"actor_claims,omitempty"`

	// ID of the User in Identity Pool that is affected by an action
	AffectedUserID string `json:"affected_user_id,omitempty" yaml:"affected_user_id,omitempty"`

	// ID of the Identity Pool of the User that is affected by an action
	AffectedUserPoolID string `json:"affected_user_pool_id,omitempty" yaml:"affected_user_pool_id,omitempty"`

	// Authorization correlation ID
	//
	// Represents the correlation ID used for the OAuth2 authorization code grant flow.
	AuthorizationCorrelationID string `json:"authorization_correlation_id,omitempty" yaml:"authorization_correlation_id,omitempty"`

	// City
	City string `json:"city,omitempty" yaml:"city,omitempty"`

	// Access request client ID related to an audit event.
	//
	// May be empty when the access is incorrect or missing.
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// Country code
	CountryCode string `json:"country_code,omitempty" yaml:"country_code,omitempty"`

	// DBFP jwt fingerprint
	DbfpFingerprint string `json:"dbfp_fingerprint,omitempty" yaml:"dbfp_fingerprint,omitempty"`

	// Device type based on the user agent (computer, tablet, phone, console, wearable, tv)
	DeviceType string `json:"device_type,omitempty" yaml:"device_type,omitempty"`

	// ID of the Group in Identity Pool
	GroupID string `json:"group_id,omitempty" yaml:"group_id,omitempty"`

	// ID of the Identity Pool
	IdentityPoolID string `json:"identity_pool_id,omitempty" yaml:"identity_pool_id,omitempty"`

	// IDP identifier
	IdpID string `json:"idp_id,omitempty" yaml:"idp_id,omitempty"`

	// IDP method
	IdpMethod string `json:"idp_method,omitempty" yaml:"idp_method,omitempty"`

	// Access request subject value from IDP related to a given audit event.
	//
	// May be empty when the access is incorrect or missing.
	IdpSubject string `json:"idp_subject,omitempty" yaml:"idp_subject,omitempty"`

	// IP address.
	//
	// It's first not empty value from: X-Forwaded-For, X-Real-IP or network socket IP address
	IP string `json:"ip,omitempty" yaml:"ip,omitempty"`

	// Latitude
	Latitude float64 `json:"latitude,omitempty" yaml:"latitude,omitempty"`

	// Longitude
	Longitude float64 `json:"longitude,omitempty" yaml:"longitude,omitempty"`

	// Access request may act claims.
	//
	// It's only populated if the token has been issued token with may_act claim.
	MayActClaims map[string]interface{} `json:"may_act_claims,omitempty" yaml:"may_act_claims,omitempty"`

	// ID of the Organization
	OrganizationID string `json:"organization_id,omitempty" yaml:"organization_id,omitempty"`

	// Request correlation ID
	//
	// Represents the correlation ID passed as X-Correlation-ID header to a HTTP request
	RequestCorrelationID string `json:"request_correlation_id,omitempty" yaml:"request_correlation_id,omitempty"`

	// risk id
	RiskID RiskID `json:"risk_id,omitempty" yaml:"risk_id,omitempty"`

	// risk loa
	RiskLoa RiskLOA `json:"risk_loa,omitempty" yaml:"risk_loa,omitempty"`

	// Session id
	//
	// Correlation ID in a login process. Returns events related to a particular login process.
	// It's empty for audit events that have been created outside login process.
	SessionID string `json:"session_id,omitempty" yaml:"session_id,omitempty"`

	// Access request subject ID related to a given audit event.
	//
	// May be empty when the access is incorrect or missing.
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`

	// Token signature
	//
	// Signature of a token that was used to perform an action that has published an audit event.
	TokenSignature string `json:"token_signature,omitempty" yaml:"token_signature,omitempty"`

	// Trace ID
	TraceID string `json:"trace_id,omitempty" yaml:"trace_id,omitempty"`

	// User-agent that describes a device name that generated the audit event.
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`

	// ID of the User in Identity Pool
	UserID string `json:"user_id,omitempty" yaml:"user_id,omitempty"`

	// ID of the Identity Pool
	UserPoolID string `json:"user_pool_id,omitempty" yaml:"user_pool_id,omitempty"`
}

// Validate validates this audit event metadata
func (m *AuditEventMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRiskID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRiskLoa(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuditEventMetadata) validateRiskID(formats strfmt.Registry) error {
	if swag.IsZero(m.RiskID) { // not required
		return nil
	}

	if err := m.RiskID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("risk_id")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("risk_id")
		}
		return err
	}

	return nil
}

func (m *AuditEventMetadata) validateRiskLoa(formats strfmt.Registry) error {
	if swag.IsZero(m.RiskLoa) { // not required
		return nil
	}

	if err := m.RiskLoa.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("risk_loa")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("risk_loa")
		}
		return err
	}

	return nil
}

// ContextValidate validate this audit event metadata based on the context it is used
func (m *AuditEventMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRiskID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRiskLoa(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuditEventMetadata) contextValidateRiskID(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.RiskID) { // not required
		return nil
	}

	if err := m.RiskID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("risk_id")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("risk_id")
		}
		return err
	}

	return nil
}

func (m *AuditEventMetadata) contextValidateRiskLoa(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.RiskLoa) { // not required
		return nil
	}

	if err := m.RiskLoa.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("risk_loa")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("risk_loa")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuditEventMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuditEventMetadata) UnmarshalBinary(b []byte) error {
	var res AuditEventMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
