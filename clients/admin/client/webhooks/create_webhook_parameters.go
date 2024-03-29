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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewCreateWebhookParams creates a new CreateWebhookParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateWebhookParams() *CreateWebhookParams {
	return &CreateWebhookParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateWebhookParamsWithTimeout creates a new CreateWebhookParams object
// with the ability to set a timeout on a request.
func NewCreateWebhookParamsWithTimeout(timeout time.Duration) *CreateWebhookParams {
	return &CreateWebhookParams{
		timeout: timeout,
	}
}

// NewCreateWebhookParamsWithContext creates a new CreateWebhookParams object
// with the ability to set a context for a request.
func NewCreateWebhookParamsWithContext(ctx context.Context) *CreateWebhookParams {
	return &CreateWebhookParams{
		Context: ctx,
	}
}

// NewCreateWebhookParamsWithHTTPClient creates a new CreateWebhookParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateWebhookParamsWithHTTPClient(client *http.Client) *CreateWebhookParams {
	return &CreateWebhookParams{
		HTTPClient: client,
	}
}

/*
CreateWebhookParams contains all the parameters to send to the API endpoint

	for the create webhook operation.

	Typically these are written to a http.Request.
*/
type CreateWebhookParams struct {

	// Webhook.
	Webhook *models.Webhook

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create webhook params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateWebhookParams) WithDefaults() *CreateWebhookParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create webhook params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateWebhookParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create webhook params
func (o *CreateWebhookParams) WithTimeout(timeout time.Duration) *CreateWebhookParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create webhook params
func (o *CreateWebhookParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create webhook params
func (o *CreateWebhookParams) WithContext(ctx context.Context) *CreateWebhookParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create webhook params
func (o *CreateWebhookParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create webhook params
func (o *CreateWebhookParams) WithHTTPClient(client *http.Client) *CreateWebhookParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create webhook params
func (o *CreateWebhookParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWebhook adds the webhook to the create webhook params
func (o *CreateWebhookParams) WithWebhook(webhook *models.Webhook) *CreateWebhookParams {
	o.SetWebhook(webhook)
	return o
}

// SetWebhook adds the webhook to the create webhook params
func (o *CreateWebhookParams) SetWebhook(webhook *models.Webhook) {
	o.Webhook = webhook
}

// WithIfMatch adds the ifMatch to the create webhook params
func (o *CreateWebhookParams) WithIfMatch(ifMatch *string) *CreateWebhookParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create webhook params
func (o *CreateWebhookParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create webhook params
func (o *CreateWebhookParams) WithWid(wid string) *CreateWebhookParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create webhook params
func (o *CreateWebhookParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateWebhookParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Webhook != nil {
		if err := r.SetBodyParam(o.Webhook); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
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
