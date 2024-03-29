// Code generated by go-swagger; DO NOT EDIT.

package webhooks

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

// NewGetWebhookParams creates a new GetWebhookParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetWebhookParams() *GetWebhookParams {
	return &GetWebhookParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetWebhookParamsWithTimeout creates a new GetWebhookParams object
// with the ability to set a timeout on a request.
func NewGetWebhookParamsWithTimeout(timeout time.Duration) *GetWebhookParams {
	return &GetWebhookParams{
		timeout: timeout,
	}
}

// NewGetWebhookParamsWithContext creates a new GetWebhookParams object
// with the ability to set a context for a request.
func NewGetWebhookParamsWithContext(ctx context.Context) *GetWebhookParams {
	return &GetWebhookParams{
		Context: ctx,
	}
}

// NewGetWebhookParamsWithHTTPClient creates a new GetWebhookParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetWebhookParamsWithHTTPClient(client *http.Client) *GetWebhookParams {
	return &GetWebhookParams{
		HTTPClient: client,
	}
}

/*
GetWebhookParams contains all the parameters to send to the API endpoint

	for the get webhook operation.

	Typically these are written to a http.Request.
*/
type GetWebhookParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* WebhookID.

	   Webhook ID
	*/
	WebhookID string

	/* Wid.

	   Authorization server id
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get webhook params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWebhookParams) WithDefaults() *GetWebhookParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get webhook params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWebhookParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get webhook params
func (o *GetWebhookParams) WithTimeout(timeout time.Duration) *GetWebhookParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get webhook params
func (o *GetWebhookParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get webhook params
func (o *GetWebhookParams) WithContext(ctx context.Context) *GetWebhookParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get webhook params
func (o *GetWebhookParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get webhook params
func (o *GetWebhookParams) WithHTTPClient(client *http.Client) *GetWebhookParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get webhook params
func (o *GetWebhookParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get webhook params
func (o *GetWebhookParams) WithIfMatch(ifMatch *string) *GetWebhookParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get webhook params
func (o *GetWebhookParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWebhookID adds the webhookID to the get webhook params
func (o *GetWebhookParams) WithWebhookID(webhookID string) *GetWebhookParams {
	o.SetWebhookID(webhookID)
	return o
}

// SetWebhookID adds the webhookId to the get webhook params
func (o *GetWebhookParams) SetWebhookID(webhookID string) {
	o.WebhookID = webhookID
}

// WithWid adds the wid to the get webhook params
func (o *GetWebhookParams) WithWid(wid string) *GetWebhookParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get webhook params
func (o *GetWebhookParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetWebhookParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param webhookID
	if err := r.SetPathParam("webhookID", o.WebhookID); err != nil {
		return err
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
