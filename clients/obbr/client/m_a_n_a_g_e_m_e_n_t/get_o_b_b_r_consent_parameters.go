// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

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

// NewGetOBBRConsentParams creates a new GetOBBRConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetOBBRConsentParams() *GetOBBRConsentParams {
	return &GetOBBRConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetOBBRConsentParamsWithTimeout creates a new GetOBBRConsentParams object
// with the ability to set a timeout on a request.
func NewGetOBBRConsentParamsWithTimeout(timeout time.Duration) *GetOBBRConsentParams {
	return &GetOBBRConsentParams{
		timeout: timeout,
	}
}

// NewGetOBBRConsentParamsWithContext creates a new GetOBBRConsentParams object
// with the ability to set a context for a request.
func NewGetOBBRConsentParamsWithContext(ctx context.Context) *GetOBBRConsentParams {
	return &GetOBBRConsentParams{
		Context: ctx,
	}
}

// NewGetOBBRConsentParamsWithHTTPClient creates a new GetOBBRConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetOBBRConsentParamsWithHTTPClient(client *http.Client) *GetOBBRConsentParams {
	return &GetOBBRConsentParams{
		HTTPClient: client,
	}
}

/*
GetOBBRConsentParams contains all the parameters to send to the API endpoint

	for the get o b b r consent operation.

	Typically these are written to a http.Request.
*/
type GetOBBRConsentParams struct {

	// ConsentID.
	ConsentID string

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get o b b r consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBBRConsentParams) WithDefaults() *GetOBBRConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get o b b r consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBBRConsentParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetOBBRConsentParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get o b b r consent params
func (o *GetOBBRConsentParams) WithTimeout(timeout time.Duration) *GetOBBRConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get o b b r consent params
func (o *GetOBBRConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get o b b r consent params
func (o *GetOBBRConsentParams) WithContext(ctx context.Context) *GetOBBRConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get o b b r consent params
func (o *GetOBBRConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get o b b r consent params
func (o *GetOBBRConsentParams) WithHTTPClient(client *http.Client) *GetOBBRConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get o b b r consent params
func (o *GetOBBRConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentID adds the consentID to the get o b b r consent params
func (o *GetOBBRConsentParams) WithConsentID(consentID string) *GetOBBRConsentParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the get o b b r consent params
func (o *GetOBBRConsentParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithWid adds the wid to the get o b b r consent params
func (o *GetOBBRConsentParams) WithWid(wid string) *GetOBBRConsentParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get o b b r consent params
func (o *GetOBBRConsentParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetOBBRConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param consentID
	if err := r.SetPathParam("consentID", o.ConsentID); err != nil {
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
