// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

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

	"github.com/cloudentity/acp-client-go/clients/cdr/models"
)

// NewDynamicClientRegistrationUpdateClientParams creates a new DynamicClientRegistrationUpdateClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDynamicClientRegistrationUpdateClientParams() *DynamicClientRegistrationUpdateClientParams {
	return &DynamicClientRegistrationUpdateClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDynamicClientRegistrationUpdateClientParamsWithTimeout creates a new DynamicClientRegistrationUpdateClientParams object
// with the ability to set a timeout on a request.
func NewDynamicClientRegistrationUpdateClientParamsWithTimeout(timeout time.Duration) *DynamicClientRegistrationUpdateClientParams {
	return &DynamicClientRegistrationUpdateClientParams{
		timeout: timeout,
	}
}

// NewDynamicClientRegistrationUpdateClientParamsWithContext creates a new DynamicClientRegistrationUpdateClientParams object
// with the ability to set a context for a request.
func NewDynamicClientRegistrationUpdateClientParamsWithContext(ctx context.Context) *DynamicClientRegistrationUpdateClientParams {
	return &DynamicClientRegistrationUpdateClientParams{
		Context: ctx,
	}
}

// NewDynamicClientRegistrationUpdateClientParamsWithHTTPClient creates a new DynamicClientRegistrationUpdateClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewDynamicClientRegistrationUpdateClientParamsWithHTTPClient(client *http.Client) *DynamicClientRegistrationUpdateClientParams {
	return &DynamicClientRegistrationUpdateClientParams{
		HTTPClient: client,
	}
}

/*
DynamicClientRegistrationUpdateClientParams contains all the parameters to send to the API endpoint

	for the dynamic client registration update client operation.

	Typically these are written to a http.Request.
*/
type DynamicClientRegistrationUpdateClientParams struct {

	// Client.
	Client *models.CDRDynamicClientRegistrationRequest

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the dynamic client registration update client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DynamicClientRegistrationUpdateClientParams) WithDefaults() *DynamicClientRegistrationUpdateClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the dynamic client registration update client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DynamicClientRegistrationUpdateClientParams) SetDefaults() {
	var (
		cidDefault = string("default")
	)

	val := DynamicClientRegistrationUpdateClientParams{
		Cid: cidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) WithTimeout(timeout time.Duration) *DynamicClientRegistrationUpdateClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) WithContext(ctx context.Context) *DynamicClientRegistrationUpdateClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) WithHTTPClient(client *http.Client) *DynamicClientRegistrationUpdateClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClient adds the client to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) WithClient(client *models.CDRDynamicClientRegistrationRequest) *DynamicClientRegistrationUpdateClientParams {
	o.SetClient(client)
	return o
}

// SetClient adds the client to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) SetClient(client *models.CDRDynamicClientRegistrationRequest) {
	o.Client = client
}

// WithCid adds the cid to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) WithCid(cid string) *DynamicClientRegistrationUpdateClientParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the dynamic client registration update client params
func (o *DynamicClientRegistrationUpdateClientParams) SetCid(cid string) {
	o.Cid = cid
}

// WriteToRequest writes these params to a swagger request
func (o *DynamicClientRegistrationUpdateClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Client != nil {
		if err := r.SetBodyParam(o.Client); err != nil {
			return err
		}
	}

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}