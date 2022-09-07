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

// NewRequestOTPChallengeParams creates a new RequestOTPChallengeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRequestOTPChallengeParams() *RequestOTPChallengeParams {
	return &RequestOTPChallengeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRequestOTPChallengeParamsWithTimeout creates a new RequestOTPChallengeParams object
// with the ability to set a timeout on a request.
func NewRequestOTPChallengeParamsWithTimeout(timeout time.Duration) *RequestOTPChallengeParams {
	return &RequestOTPChallengeParams{
		timeout: timeout,
	}
}

// NewRequestOTPChallengeParamsWithContext creates a new RequestOTPChallengeParams object
// with the ability to set a context for a request.
func NewRequestOTPChallengeParamsWithContext(ctx context.Context) *RequestOTPChallengeParams {
	return &RequestOTPChallengeParams{
		Context: ctx,
	}
}

// NewRequestOTPChallengeParamsWithHTTPClient creates a new RequestOTPChallengeParams object
// with the ability to set a custom HTTPClient for a request.
func NewRequestOTPChallengeParamsWithHTTPClient(client *http.Client) *RequestOTPChallengeParams {
	return &RequestOTPChallengeParams{
		HTTPClient: client,
	}
}

/* RequestOTPChallengeParams contains all the parameters to send to the API endpoint
   for the request o t p challenge operation.

   Typically these are written to a http.Request.
*/
type RequestOTPChallengeParams struct {

	// RequestOTPChallenge.
	RequestOTPChallenge *models.RequestOTPChallenge

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the request o t p challenge params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RequestOTPChallengeParams) WithDefaults() *RequestOTPChallengeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the request o t p challenge params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RequestOTPChallengeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the request o t p challenge params
func (o *RequestOTPChallengeParams) WithTimeout(timeout time.Duration) *RequestOTPChallengeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the request o t p challenge params
func (o *RequestOTPChallengeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the request o t p challenge params
func (o *RequestOTPChallengeParams) WithContext(ctx context.Context) *RequestOTPChallengeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the request o t p challenge params
func (o *RequestOTPChallengeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the request o t p challenge params
func (o *RequestOTPChallengeParams) WithHTTPClient(client *http.Client) *RequestOTPChallengeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the request o t p challenge params
func (o *RequestOTPChallengeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequestOTPChallenge adds the requestOTPChallenge to the request o t p challenge params
func (o *RequestOTPChallengeParams) WithRequestOTPChallenge(requestOTPChallenge *models.RequestOTPChallenge) *RequestOTPChallengeParams {
	o.SetRequestOTPChallenge(requestOTPChallenge)
	return o
}

// SetRequestOTPChallenge adds the requestOTPChallenge to the request o t p challenge params
func (o *RequestOTPChallengeParams) SetRequestOTPChallenge(requestOTPChallenge *models.RequestOTPChallenge) {
	o.RequestOTPChallenge = requestOTPChallenge
}

// WithIPID adds the iPID to the request o t p challenge params
func (o *RequestOTPChallengeParams) WithIPID(iPID string) *RequestOTPChallengeParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the request o t p challenge params
func (o *RequestOTPChallengeParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *RequestOTPChallengeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.RequestOTPChallenge != nil {
		if err := r.SetBodyParam(o.RequestOTPChallenge); err != nil {
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
