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

	"github.com/cloudentity/acp-client-go/clients/cdr/models"
)

// NewListCDRArrangementsParams creates a new ListCDRArrangementsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListCDRArrangementsParams() *ListCDRArrangementsParams {
	return &ListCDRArrangementsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListCDRArrangementsParamsWithTimeout creates a new ListCDRArrangementsParams object
// with the ability to set a timeout on a request.
func NewListCDRArrangementsParamsWithTimeout(timeout time.Duration) *ListCDRArrangementsParams {
	return &ListCDRArrangementsParams{
		timeout: timeout,
	}
}

// NewListCDRArrangementsParamsWithContext creates a new ListCDRArrangementsParams object
// with the ability to set a context for a request.
func NewListCDRArrangementsParamsWithContext(ctx context.Context) *ListCDRArrangementsParams {
	return &ListCDRArrangementsParams{
		Context: ctx,
	}
}

// NewListCDRArrangementsParamsWithHTTPClient creates a new ListCDRArrangementsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListCDRArrangementsParamsWithHTTPClient(client *http.Client) *ListCDRArrangementsParams {
	return &ListCDRArrangementsParams{
		HTTPClient: client,
	}
}

/*
ListCDRArrangementsParams contains all the parameters to send to the API endpoint

	for the list c d r arrangements operation.

	Typically these are written to a http.Request.
*/
type ListCDRArrangementsParams struct {

	// ConsentsRequest.
	ConsentsRequest *models.CDRConsentsRequest

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list c d r arrangements params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListCDRArrangementsParams) WithDefaults() *ListCDRArrangementsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list c d r arrangements params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListCDRArrangementsParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ListCDRArrangementsParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list c d r arrangements params
func (o *ListCDRArrangementsParams) WithTimeout(timeout time.Duration) *ListCDRArrangementsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list c d r arrangements params
func (o *ListCDRArrangementsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list c d r arrangements params
func (o *ListCDRArrangementsParams) WithContext(ctx context.Context) *ListCDRArrangementsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list c d r arrangements params
func (o *ListCDRArrangementsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list c d r arrangements params
func (o *ListCDRArrangementsParams) WithHTTPClient(client *http.Client) *ListCDRArrangementsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list c d r arrangements params
func (o *ListCDRArrangementsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentsRequest adds the consentsRequest to the list c d r arrangements params
func (o *ListCDRArrangementsParams) WithConsentsRequest(consentsRequest *models.CDRConsentsRequest) *ListCDRArrangementsParams {
	o.SetConsentsRequest(consentsRequest)
	return o
}

// SetConsentsRequest adds the consentsRequest to the list c d r arrangements params
func (o *ListCDRArrangementsParams) SetConsentsRequest(consentsRequest *models.CDRConsentsRequest) {
	o.ConsentsRequest = consentsRequest
}

// WithWid adds the wid to the list c d r arrangements params
func (o *ListCDRArrangementsParams) WithWid(wid string) *ListCDRArrangementsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list c d r arrangements params
func (o *ListCDRArrangementsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListCDRArrangementsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ConsentsRequest != nil {
		if err := r.SetBodyParam(o.ConsentsRequest); err != nil {
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
