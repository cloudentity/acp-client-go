// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

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

// NewInspectOTPParams creates a new InspectOTPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewInspectOTPParams() *InspectOTPParams {
	return &InspectOTPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewInspectOTPParamsWithTimeout creates a new InspectOTPParams object
// with the ability to set a timeout on a request.
func NewInspectOTPParamsWithTimeout(timeout time.Duration) *InspectOTPParams {
	return &InspectOTPParams{
		timeout: timeout,
	}
}

// NewInspectOTPParamsWithContext creates a new InspectOTPParams object
// with the ability to set a context for a request.
func NewInspectOTPParamsWithContext(ctx context.Context) *InspectOTPParams {
	return &InspectOTPParams{
		Context: ctx,
	}
}

// NewInspectOTPParamsWithHTTPClient creates a new InspectOTPParams object
// with the ability to set a custom HTTPClient for a request.
func NewInspectOTPParamsWithHTTPClient(client *http.Client) *InspectOTPParams {
	return &InspectOTPParams{
		HTTPClient: client,
	}
}

/* InspectOTPParams contains all the parameters to send to the API endpoint
   for the inspect o t p operation.

   Typically these are written to a http.Request.
*/
type InspectOTPParams struct {

	// InspectOTP.
	InspectOTP *models.InspectOTP

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the inspect o t p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *InspectOTPParams) WithDefaults() *InspectOTPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the inspect o t p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *InspectOTPParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the inspect o t p params
func (o *InspectOTPParams) WithTimeout(timeout time.Duration) *InspectOTPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the inspect o t p params
func (o *InspectOTPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the inspect o t p params
func (o *InspectOTPParams) WithContext(ctx context.Context) *InspectOTPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the inspect o t p params
func (o *InspectOTPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the inspect o t p params
func (o *InspectOTPParams) WithHTTPClient(client *http.Client) *InspectOTPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the inspect o t p params
func (o *InspectOTPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithInspectOTP adds the inspectOTP to the inspect o t p params
func (o *InspectOTPParams) WithInspectOTP(inspectOTP *models.InspectOTP) *InspectOTPParams {
	o.SetInspectOTP(inspectOTP)
	return o
}

// SetInspectOTP adds the inspectOTP to the inspect o t p params
func (o *InspectOTPParams) SetInspectOTP(inspectOTP *models.InspectOTP) {
	o.InspectOTP = inspectOTP
}

// WithIPID adds the iPID to the inspect o t p params
func (o *InspectOTPParams) WithIPID(iPID string) *InspectOTPParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the inspect o t p params
func (o *InspectOTPParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *InspectOTPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.InspectOTP != nil {
		if err := r.SetBodyParam(o.InspectOTP); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}