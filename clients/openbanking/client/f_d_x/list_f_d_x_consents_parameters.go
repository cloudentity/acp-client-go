// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

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

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// NewListFDXConsentsParams creates a new ListFDXConsentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListFDXConsentsParams() *ListFDXConsentsParams {
	return &ListFDXConsentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListFDXConsentsParamsWithTimeout creates a new ListFDXConsentsParams object
// with the ability to set a timeout on a request.
func NewListFDXConsentsParamsWithTimeout(timeout time.Duration) *ListFDXConsentsParams {
	return &ListFDXConsentsParams{
		timeout: timeout,
	}
}

// NewListFDXConsentsParamsWithContext creates a new ListFDXConsentsParams object
// with the ability to set a context for a request.
func NewListFDXConsentsParamsWithContext(ctx context.Context) *ListFDXConsentsParams {
	return &ListFDXConsentsParams{
		Context: ctx,
	}
}

// NewListFDXConsentsParamsWithHTTPClient creates a new ListFDXConsentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListFDXConsentsParamsWithHTTPClient(client *http.Client) *ListFDXConsentsParams {
	return &ListFDXConsentsParams{
		HTTPClient: client,
	}
}

/*
ListFDXConsentsParams contains all the parameters to send to the API endpoint

	for the list f d x consents operation.

	Typically these are written to a http.Request.
*/
type ListFDXConsentsParams struct {

	// FDXConsentsRequest.
	FDXConsentsRequest *models.FDXConsentsRequest

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list f d x consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListFDXConsentsParams) WithDefaults() *ListFDXConsentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list f d x consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListFDXConsentsParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ListFDXConsentsParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list f d x consents params
func (o *ListFDXConsentsParams) WithTimeout(timeout time.Duration) *ListFDXConsentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list f d x consents params
func (o *ListFDXConsentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list f d x consents params
func (o *ListFDXConsentsParams) WithContext(ctx context.Context) *ListFDXConsentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list f d x consents params
func (o *ListFDXConsentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list f d x consents params
func (o *ListFDXConsentsParams) WithHTTPClient(client *http.Client) *ListFDXConsentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list f d x consents params
func (o *ListFDXConsentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFDXConsentsRequest adds the fDXConsentsRequest to the list f d x consents params
func (o *ListFDXConsentsParams) WithFDXConsentsRequest(fDXConsentsRequest *models.FDXConsentsRequest) *ListFDXConsentsParams {
	o.SetFDXConsentsRequest(fDXConsentsRequest)
	return o
}

// SetFDXConsentsRequest adds the fDXConsentsRequest to the list f d x consents params
func (o *ListFDXConsentsParams) SetFDXConsentsRequest(fDXConsentsRequest *models.FDXConsentsRequest) {
	o.FDXConsentsRequest = fDXConsentsRequest
}

// WithWid adds the wid to the list f d x consents params
func (o *ListFDXConsentsParams) WithWid(wid string) *ListFDXConsentsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list f d x consents params
func (o *ListFDXConsentsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListFDXConsentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.FDXConsentsRequest != nil {
		if err := r.SetBodyParam(o.FDXConsentsRequest); err != nil {
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
