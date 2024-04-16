// Code generated by go-swagger; DO NOT EDIT.

package users

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

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// NewSendActivationMessageParams creates a new SendActivationMessageParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSendActivationMessageParams() *SendActivationMessageParams {
	return &SendActivationMessageParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSendActivationMessageParamsWithTimeout creates a new SendActivationMessageParams object
// with the ability to set a timeout on a request.
func NewSendActivationMessageParamsWithTimeout(timeout time.Duration) *SendActivationMessageParams {
	return &SendActivationMessageParams{
		timeout: timeout,
	}
}

// NewSendActivationMessageParamsWithContext creates a new SendActivationMessageParams object
// with the ability to set a context for a request.
func NewSendActivationMessageParamsWithContext(ctx context.Context) *SendActivationMessageParams {
	return &SendActivationMessageParams{
		Context: ctx,
	}
}

// NewSendActivationMessageParamsWithHTTPClient creates a new SendActivationMessageParams object
// with the ability to set a custom HTTPClient for a request.
func NewSendActivationMessageParamsWithHTTPClient(client *http.Client) *SendActivationMessageParams {
	return &SendActivationMessageParams{
		HTTPClient: client,
	}
}

/*
SendActivationMessageParams contains all the parameters to send to the API endpoint

	for the send activation message operation.

	Typically these are written to a http.Request.
*/
type SendActivationMessageParams struct {

	// SendActivationMessage.
	SendActivationMessage *models.RequestActivation

	/* CodeTypeInMessage.

	   Code type in message

	   Default: "link"
	*/
	CodeTypeInMessage *string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	/* Mode.

	     optional mode
	Mode

	     Default: "registration"
	*/
	Mode *string

	/* PostActivationURL.

	     optional URL where user will be asked to sign in after successful activation
	PostActivationURL
	*/
	PostActivationURL *string

	/* ServerID.

	     optional server's identifier (used for themes etc.)
	ServerID
	*/
	ServerID *string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the send activation message params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SendActivationMessageParams) WithDefaults() *SendActivationMessageParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the send activation message params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SendActivationMessageParams) SetDefaults() {
	var (
		codeTypeInMessageDefault = string("link")

		modeDefault = string("registration")
	)

	val := SendActivationMessageParams{
		CodeTypeInMessage: &codeTypeInMessageDefault,
		Mode:              &modeDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the send activation message params
func (o *SendActivationMessageParams) WithTimeout(timeout time.Duration) *SendActivationMessageParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the send activation message params
func (o *SendActivationMessageParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the send activation message params
func (o *SendActivationMessageParams) WithContext(ctx context.Context) *SendActivationMessageParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the send activation message params
func (o *SendActivationMessageParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the send activation message params
func (o *SendActivationMessageParams) WithHTTPClient(client *http.Client) *SendActivationMessageParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the send activation message params
func (o *SendActivationMessageParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSendActivationMessage adds the sendActivationMessage to the send activation message params
func (o *SendActivationMessageParams) WithSendActivationMessage(sendActivationMessage *models.RequestActivation) *SendActivationMessageParams {
	o.SetSendActivationMessage(sendActivationMessage)
	return o
}

// SetSendActivationMessage adds the sendActivationMessage to the send activation message params
func (o *SendActivationMessageParams) SetSendActivationMessage(sendActivationMessage *models.RequestActivation) {
	o.SendActivationMessage = sendActivationMessage
}

// WithCodeTypeInMessage adds the codeTypeInMessage to the send activation message params
func (o *SendActivationMessageParams) WithCodeTypeInMessage(codeTypeInMessage *string) *SendActivationMessageParams {
	o.SetCodeTypeInMessage(codeTypeInMessage)
	return o
}

// SetCodeTypeInMessage adds the codeTypeInMessage to the send activation message params
func (o *SendActivationMessageParams) SetCodeTypeInMessage(codeTypeInMessage *string) {
	o.CodeTypeInMessage = codeTypeInMessage
}

// WithIfMatch adds the ifMatch to the send activation message params
func (o *SendActivationMessageParams) WithIfMatch(ifMatch *string) *SendActivationMessageParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the send activation message params
func (o *SendActivationMessageParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the send activation message params
func (o *SendActivationMessageParams) WithIPID(iPID string) *SendActivationMessageParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the send activation message params
func (o *SendActivationMessageParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithMode adds the mode to the send activation message params
func (o *SendActivationMessageParams) WithMode(mode *string) *SendActivationMessageParams {
	o.SetMode(mode)
	return o
}

// SetMode adds the mode to the send activation message params
func (o *SendActivationMessageParams) SetMode(mode *string) {
	o.Mode = mode
}

// WithPostActivationURL adds the postActivationURL to the send activation message params
func (o *SendActivationMessageParams) WithPostActivationURL(postActivationURL *string) *SendActivationMessageParams {
	o.SetPostActivationURL(postActivationURL)
	return o
}

// SetPostActivationURL adds the postActivationUrl to the send activation message params
func (o *SendActivationMessageParams) SetPostActivationURL(postActivationURL *string) {
	o.PostActivationURL = postActivationURL
}

// WithServerID adds the serverID to the send activation message params
func (o *SendActivationMessageParams) WithServerID(serverID *string) *SendActivationMessageParams {
	o.SetServerID(serverID)
	return o
}

// SetServerID adds the serverId to the send activation message params
func (o *SendActivationMessageParams) SetServerID(serverID *string) {
	o.ServerID = serverID
}

// WithUserID adds the userID to the send activation message params
func (o *SendActivationMessageParams) WithUserID(userID string) *SendActivationMessageParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the send activation message params
func (o *SendActivationMessageParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *SendActivationMessageParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SendActivationMessage != nil {
		if err := r.SetBodyParam(o.SendActivationMessage); err != nil {
			return err
		}
	}

	if o.CodeTypeInMessage != nil {

		// query param code_type_in_message
		var qrCodeTypeInMessage string

		if o.CodeTypeInMessage != nil {
			qrCodeTypeInMessage = *o.CodeTypeInMessage
		}
		qCodeTypeInMessage := qrCodeTypeInMessage
		if qCodeTypeInMessage != "" {

			if err := r.SetQueryParam("code_type_in_message", qCodeTypeInMessage); err != nil {
				return err
			}
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	if o.Mode != nil {

		// query param mode
		var qrMode string

		if o.Mode != nil {
			qrMode = *o.Mode
		}
		qMode := qrMode
		if qMode != "" {

			if err := r.SetQueryParam("mode", qMode); err != nil {
				return err
			}
		}
	}

	if o.PostActivationURL != nil {

		// query param post_activation_url
		var qrPostActivationURL string

		if o.PostActivationURL != nil {
			qrPostActivationURL = *o.PostActivationURL
		}
		qPostActivationURL := qrPostActivationURL
		if qPostActivationURL != "" {

			if err := r.SetQueryParam("post_activation_url", qPostActivationURL); err != nil {
				return err
			}
		}
	}

	if o.ServerID != nil {

		// query param server_id
		var qrServerID string

		if o.ServerID != nil {
			qrServerID = *o.ServerID
		}
		qServerID := qrServerID
		if qServerID != "" {

			if err := r.SetQueryParam("server_id", qServerID); err != nil {
				return err
			}
		}
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
