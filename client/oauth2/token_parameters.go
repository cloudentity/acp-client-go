// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewTokenParams creates a new TokenParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewTokenParams() *TokenParams {
	return &TokenParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewTokenParamsWithTimeout creates a new TokenParams object
// with the ability to set a timeout on a request.
func NewTokenParamsWithTimeout(timeout time.Duration) *TokenParams {
	return &TokenParams{
		timeout: timeout,
	}
}

// NewTokenParamsWithContext creates a new TokenParams object
// with the ability to set a context for a request.
func NewTokenParamsWithContext(ctx context.Context) *TokenParams {
	return &TokenParams{
		Context: ctx,
	}
}

// NewTokenParamsWithHTTPClient creates a new TokenParams object
// with the ability to set a custom HTTPClient for a request.
func NewTokenParamsWithHTTPClient(client *http.Client) *TokenParams {
	return &TokenParams{
		HTTPClient: client,
	}
}

/* TokenParams contains all the parameters to send to the API endpoint
   for the token operation.

   Typically these are written to a http.Request.
*/
type TokenParams struct {

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	// ClientID.
	ClientID *string

	// ClientSecret.
	ClientSecret *string

	// Code.
	Code *string

	// GrantType.
	GrantType string

	// Password.
	Password *string

	// RedirectURI.
	RedirectURI *string

	// RefreshToken.
	RefreshToken *string

	// Scope.
	Scope *string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	// Username.
	Username *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the token params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TokenParams) WithDefaults() *TokenParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the token params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TokenParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := TokenParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the token params
func (o *TokenParams) WithTimeout(timeout time.Duration) *TokenParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the token params
func (o *TokenParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the token params
func (o *TokenParams) WithContext(ctx context.Context) *TokenParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the token params
func (o *TokenParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the token params
func (o *TokenParams) WithHTTPClient(client *http.Client) *TokenParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the token params
func (o *TokenParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the token params
func (o *TokenParams) WithAid(aid string) *TokenParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the token params
func (o *TokenParams) SetAid(aid string) {
	o.Aid = aid
}

// WithClientID adds the clientID to the token params
func (o *TokenParams) WithClientID(clientID *string) *TokenParams {
	o.SetClientID(clientID)
	return o
}

// SetClientID adds the clientId to the token params
func (o *TokenParams) SetClientID(clientID *string) {
	o.ClientID = clientID
}

// WithClientSecret adds the clientSecret to the token params
func (o *TokenParams) WithClientSecret(clientSecret *string) *TokenParams {
	o.SetClientSecret(clientSecret)
	return o
}

// SetClientSecret adds the clientSecret to the token params
func (o *TokenParams) SetClientSecret(clientSecret *string) {
	o.ClientSecret = clientSecret
}

// WithCode adds the code to the token params
func (o *TokenParams) WithCode(code *string) *TokenParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the token params
func (o *TokenParams) SetCode(code *string) {
	o.Code = code
}

// WithGrantType adds the grantType to the token params
func (o *TokenParams) WithGrantType(grantType string) *TokenParams {
	o.SetGrantType(grantType)
	return o
}

// SetGrantType adds the grantType to the token params
func (o *TokenParams) SetGrantType(grantType string) {
	o.GrantType = grantType
}

// WithPassword adds the password to the token params
func (o *TokenParams) WithPassword(password *string) *TokenParams {
	o.SetPassword(password)
	return o
}

// SetPassword adds the password to the token params
func (o *TokenParams) SetPassword(password *string) {
	o.Password = password
}

// WithRedirectURI adds the redirectURI to the token params
func (o *TokenParams) WithRedirectURI(redirectURI *string) *TokenParams {
	o.SetRedirectURI(redirectURI)
	return o
}

// SetRedirectURI adds the redirectUri to the token params
func (o *TokenParams) SetRedirectURI(redirectURI *string) {
	o.RedirectURI = redirectURI
}

// WithRefreshToken adds the refreshToken to the token params
func (o *TokenParams) WithRefreshToken(refreshToken *string) *TokenParams {
	o.SetRefreshToken(refreshToken)
	return o
}

// SetRefreshToken adds the refreshToken to the token params
func (o *TokenParams) SetRefreshToken(refreshToken *string) {
	o.RefreshToken = refreshToken
}

// WithScope adds the scope to the token params
func (o *TokenParams) WithScope(scope *string) *TokenParams {
	o.SetScope(scope)
	return o
}

// SetScope adds the scope to the token params
func (o *TokenParams) SetScope(scope *string) {
	o.Scope = scope
}

// WithTid adds the tid to the token params
func (o *TokenParams) WithTid(tid string) *TokenParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the token params
func (o *TokenParams) SetTid(tid string) {
	o.Tid = tid
}

// WithUsername adds the username to the token params
func (o *TokenParams) WithUsername(username *string) *TokenParams {
	o.SetUsername(username)
	return o
}

// SetUsername adds the username to the token params
func (o *TokenParams) SetUsername(username *string) {
	o.Username = username
}

// WriteToRequest writes these params to a swagger request
func (o *TokenParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	if o.ClientID != nil {

		// form param client_id
		var frClientID string
		if o.ClientID != nil {
			frClientID = *o.ClientID
		}
		fClientID := frClientID
		if fClientID != "" {
			if err := r.SetFormParam("client_id", fClientID); err != nil {
				return err
			}
		}
	}

	if o.ClientSecret != nil {

		// form param client_secret
		var frClientSecret string
		if o.ClientSecret != nil {
			frClientSecret = *o.ClientSecret
		}
		fClientSecret := frClientSecret
		if fClientSecret != "" {
			if err := r.SetFormParam("client_secret", fClientSecret); err != nil {
				return err
			}
		}
	}

	if o.Code != nil {

		// form param code
		var frCode string
		if o.Code != nil {
			frCode = *o.Code
		}
		fCode := frCode
		if fCode != "" {
			if err := r.SetFormParam("code", fCode); err != nil {
				return err
			}
		}
	}

	// form param grant_type
	frGrantType := o.GrantType
	fGrantType := frGrantType
	if fGrantType != "" {
		if err := r.SetFormParam("grant_type", fGrantType); err != nil {
			return err
		}
	}

	if o.Password != nil {

		// form param password
		var frPassword string
		if o.Password != nil {
			frPassword = *o.Password
		}
		fPassword := frPassword
		if fPassword != "" {
			if err := r.SetFormParam("password", fPassword); err != nil {
				return err
			}
		}
	}

	if o.RedirectURI != nil {

		// form param redirect_uri
		var frRedirectURI string
		if o.RedirectURI != nil {
			frRedirectURI = *o.RedirectURI
		}
		fRedirectURI := frRedirectURI
		if fRedirectURI != "" {
			if err := r.SetFormParam("redirect_uri", fRedirectURI); err != nil {
				return err
			}
		}
	}

	if o.RefreshToken != nil {

		// form param refresh_token
		var frRefreshToken string
		if o.RefreshToken != nil {
			frRefreshToken = *o.RefreshToken
		}
		fRefreshToken := frRefreshToken
		if fRefreshToken != "" {
			if err := r.SetFormParam("refresh_token", fRefreshToken); err != nil {
				return err
			}
		}
	}

	if o.Scope != nil {

		// form param scope
		var frScope string
		if o.Scope != nil {
			frScope = *o.Scope
		}
		fScope := frScope
		if fScope != "" {
			if err := r.SetFormParam("scope", fScope); err != nil {
				return err
			}
		}
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if o.Username != nil {

		// form param username
		var frUsername string
		if o.Username != nil {
			frUsername = *o.Username
		}
		fUsername := frUsername
		if fUsername != "" {
			if err := r.SetFormParam("username", fUsername); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
