// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SecureOptions nolint
//
// swagger:model SecureOptions
type SecureOptions struct {

	// AllowedHosts is a slice of fully qualified domain names that are allowed. Default is an empty slice, which allows any and all host names.
	AllowedHosts []string `json:"AllowedHosts" yaml:"AllowedHosts"`

	// AllowedHostsAreRegex determines, if the provided `AllowedHosts` slice contains valid regular expressions. If this flag is set to true, every request's host will be checked against these expressions. Default is false.
	AllowedHostsAreRegex bool `json:"AllowedHostsAreRegex,omitempty" yaml:"AllowedHostsAreRegex,omitempty"`

	// If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
	BrowserXSSFilter bool `json:"BrowserXssFilter,omitempty" yaml:"BrowserXssFilter,omitempty"`

	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
	ContentSecurityPolicy string `json:"ContentSecurityPolicy,omitempty" yaml:"ContentSecurityPolicy,omitempty"`

	// ContentSecurityPolicyReportOnly allows the Content-Security-Policy-Report-Only header value to be set with a custom value. Default is "".
	ContentSecurityPolicyReportOnly string `json:"ContentSecurityPolicyReportOnly,omitempty" yaml:"ContentSecurityPolicyReportOnly,omitempty"`

	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
	ContentTypeNosniff bool `json:"ContentTypeNosniff,omitempty" yaml:"ContentTypeNosniff,omitempty"`

	// CrossOriginOpenerPolicy allows you to ensure a top-level document does not share a browsing context group with cross-origin documents. Default is "".
	// Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
	CrossOriginOpenerPolicy string `json:"CrossOriginOpenerPolicy,omitempty" yaml:"CrossOriginOpenerPolicy,omitempty"`

	// CustomBrowserXssValue allows the X-XSS-Protection header value to be set with a custom value. This overrides the BrowserXssFilter option. Default is "".
	CustomBrowserXSSValue string `json:"CustomBrowserXssValue,omitempty" yaml:"CustomBrowserXssValue,omitempty"`

	// Passing a template string will replace `$NONCE` with a dynamic nonce value of 16 bytes for each request which can be later retrieved using the Nonce function.
	// Eg: script-src $NONCE -> script-src 'nonce-a2ZobGFoZg=='
	// CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. Default is "".
	CustomFrameOptionsValue string `json:"CustomFrameOptionsValue,omitempty" yaml:"CustomFrameOptionsValue,omitempty"`

	// ExpectCTHeader allows the Expect-CT header value to be set with a custom value. Default is "".
	ExpectCTHeader string `json:"ExpectCTHeader,omitempty" yaml:"ExpectCTHeader,omitempty"`

	// FeaturePolicy allows to selectively enable and disable use of various browser features and APIs. Default is "".
	// Deprecated: This header has been renamed to Permissions-Policy.
	FeaturePolicy string `json:"FeaturePolicy,omitempty" yaml:"FeaturePolicy,omitempty"`

	// If ForceSTSHeader is set to true, the STS header will be added even when the connection is HTTP. Default is false.
	ForceSTSHeader bool `json:"ForceSTSHeader,omitempty" yaml:"ForceSTSHeader,omitempty"`

	// If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
	FrameDeny bool `json:"FrameDeny,omitempty" yaml:"FrameDeny,omitempty"`

	// HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
	HostsProxyHeaders []string `json:"HostsProxyHeaders" yaml:"HostsProxyHeaders"`

	// When developing, the AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain... so set this to true for dev environment.
	// If you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false. Default if false.
	IsDevelopment bool `json:"IsDevelopment,omitempty" yaml:"IsDevelopment,omitempty"`

	// PermissionsPolicy allows to selectively enable and disable use of various browser features and APIs. Default is "".
	PermissionsPolicy string `json:"PermissionsPolicy,omitempty" yaml:"PermissionsPolicy,omitempty"`

	// PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
	// Deprecated: This feature is no longer recommended. Though some browsers might still support it, it may have already been removed from the relevant web standards, may be in the process of being dropped, or may only be kept for compatibility purposes. Avoid using it, and update existing code if possible.
	PublicKey string `json:"PublicKey,omitempty" yaml:"PublicKey,omitempty"`

	// ReferrerPolicy allows sites to control when browsers will pass the Referer header to other sites. Default is "".
	ReferrerPolicy string `json:"ReferrerPolicy,omitempty" yaml:"ReferrerPolicy,omitempty"`

	// If SSLForceHost is true and SSLHost is set, requests will be forced to use SSLHost even the ones that are already using SSL. Default is false.
	SSLForceHost bool `json:"SSLForceHost,omitempty" yaml:"SSLForceHost,omitempty"`

	// SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
	SSLHost string `json:"SSLHost,omitempty" yaml:"SSLHost,omitempty"`

	// SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
	SSLProxyHeaders map[string]string `json:"SSLProxyHeaders,omitempty" yaml:"SSLProxyHeaders,omitempty"`

	// If SSLRedirect is set to true, then only allow https requests. Default is false.
	SSLRedirect bool `json:"SSLRedirect,omitempty" yaml:"SSLRedirect,omitempty"`

	// If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
	SSLTemporaryRedirect bool `json:"SSLTemporaryRedirect,omitempty" yaml:"SSLTemporaryRedirect,omitempty"`

	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool `json:"STSIncludeSubdomains,omitempty" yaml:"STSIncludeSubdomains,omitempty"`

	// If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
	STSPreload bool `json:"STSPreload,omitempty" yaml:"STSPreload,omitempty"`

	// STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
	STSSeconds int64 `json:"STSSeconds,omitempty" yaml:"STSSeconds,omitempty"`

	// SecureContextKey allows a custom key to be specified for context storage.
	SecureContextKey string `json:"SecureContextKey,omitempty" yaml:"SecureContextKey,omitempty"`
}

// Validate validates this secure options
func (m *SecureOptions) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this secure options based on context it is used
func (m *SecureOptions) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SecureOptions) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SecureOptions) UnmarshalBinary(b []byte) error {
	var res SecureOptions
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}