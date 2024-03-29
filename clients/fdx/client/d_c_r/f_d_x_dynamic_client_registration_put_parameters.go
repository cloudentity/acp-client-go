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

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// NewFDXDynamicClientRegistrationPutParams creates a new FDXDynamicClientRegistrationPutParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewFDXDynamicClientRegistrationPutParams() *FDXDynamicClientRegistrationPutParams {
	return &FDXDynamicClientRegistrationPutParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewFDXDynamicClientRegistrationPutParamsWithTimeout creates a new FDXDynamicClientRegistrationPutParams object
// with the ability to set a timeout on a request.
func NewFDXDynamicClientRegistrationPutParamsWithTimeout(timeout time.Duration) *FDXDynamicClientRegistrationPutParams {
	return &FDXDynamicClientRegistrationPutParams{
		timeout: timeout,
	}
}

// NewFDXDynamicClientRegistrationPutParamsWithContext creates a new FDXDynamicClientRegistrationPutParams object
// with the ability to set a context for a request.
func NewFDXDynamicClientRegistrationPutParamsWithContext(ctx context.Context) *FDXDynamicClientRegistrationPutParams {
	return &FDXDynamicClientRegistrationPutParams{
		Context: ctx,
	}
}

// NewFDXDynamicClientRegistrationPutParamsWithHTTPClient creates a new FDXDynamicClientRegistrationPutParams object
// with the ability to set a custom HTTPClient for a request.
func NewFDXDynamicClientRegistrationPutParamsWithHTTPClient(client *http.Client) *FDXDynamicClientRegistrationPutParams {
	return &FDXDynamicClientRegistrationPutParams{
		HTTPClient: client,
	}
}

/*
FDXDynamicClientRegistrationPutParams contains all the parameters to send to the API endpoint

	for the f d x dynamic client registration put operation.

	Typically these are written to a http.Request.
*/
type FDXDynamicClientRegistrationPutParams struct {

	// Client.
	Client *models.FDXDynamicClientRegistrationRequest

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the f d x dynamic client registration put params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FDXDynamicClientRegistrationPutParams) WithDefaults() *FDXDynamicClientRegistrationPutParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the f d x dynamic client registration put params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FDXDynamicClientRegistrationPutParams) SetDefaults() {
	var (
		cidDefault = string("default")
	)

	val := FDXDynamicClientRegistrationPutParams{
		Cid: cidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) WithTimeout(timeout time.Duration) *FDXDynamicClientRegistrationPutParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) WithContext(ctx context.Context) *FDXDynamicClientRegistrationPutParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) WithHTTPClient(client *http.Client) *FDXDynamicClientRegistrationPutParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClient adds the client to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) WithClient(client *models.FDXDynamicClientRegistrationRequest) *FDXDynamicClientRegistrationPutParams {
	o.SetClient(client)
	return o
}

// SetClient adds the client to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) SetClient(client *models.FDXDynamicClientRegistrationRequest) {
	o.Client = client
}

// WithCid adds the cid to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) WithCid(cid string) *FDXDynamicClientRegistrationPutParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the f d x dynamic client registration put params
func (o *FDXDynamicClientRegistrationPutParams) SetCid(cid string) {
	o.Cid = cid
}

// WriteToRequest writes these params to a swagger request
func (o *FDXDynamicClientRegistrationPutParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
