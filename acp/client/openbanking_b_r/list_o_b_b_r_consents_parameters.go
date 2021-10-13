// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

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

	"github.com/cloudentity/acp-client-go/acp/models"
)

// NewListOBBRConsentsParams creates a new ListOBBRConsentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListOBBRConsentsParams() *ListOBBRConsentsParams {
	return &ListOBBRConsentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListOBBRConsentsParamsWithTimeout creates a new ListOBBRConsentsParams object
// with the ability to set a timeout on a request.
func NewListOBBRConsentsParamsWithTimeout(timeout time.Duration) *ListOBBRConsentsParams {
	return &ListOBBRConsentsParams{
		timeout: timeout,
	}
}

// NewListOBBRConsentsParamsWithContext creates a new ListOBBRConsentsParams object
// with the ability to set a context for a request.
func NewListOBBRConsentsParamsWithContext(ctx context.Context) *ListOBBRConsentsParams {
	return &ListOBBRConsentsParams{
		Context: ctx,
	}
}

// NewListOBBRConsentsParamsWithHTTPClient creates a new ListOBBRConsentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListOBBRConsentsParamsWithHTTPClient(client *http.Client) *ListOBBRConsentsParams {
	return &ListOBBRConsentsParams{
		HTTPClient: client,
	}
}

/* ListOBBRConsentsParams contains all the parameters to send to the API endpoint
   for the list o b b r consents operation.

   Typically these are written to a http.Request.
*/
type ListOBBRConsentsParams struct {

	// ConsentsRequest.
	ConsentsRequest *models.ConsentsRequest

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	// Tid.
	//
	// Default: "default"
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list o b b r consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListOBBRConsentsParams) WithDefaults() *ListOBBRConsentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list o b b r consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListOBBRConsentsParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := ListOBBRConsentsParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithTimeout(timeout time.Duration) *ListOBBRConsentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithContext(ctx context.Context) *ListOBBRConsentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithHTTPClient(client *http.Client) *ListOBBRConsentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentsRequest adds the consentsRequest to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithConsentsRequest(consentsRequest *models.ConsentsRequest) *ListOBBRConsentsParams {
	o.SetConsentsRequest(consentsRequest)
	return o
}

// SetConsentsRequest adds the consentsRequest to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetConsentsRequest(consentsRequest *models.ConsentsRequest) {
	o.ConsentsRequest = consentsRequest
}

// WithAid adds the aid to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithAid(aid string) *ListOBBRConsentsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the list o b b r consents params
func (o *ListOBBRConsentsParams) WithTid(tid string) *ListOBBRConsentsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list o b b r consents params
func (o *ListOBBRConsentsParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ListOBBRConsentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ConsentsRequest != nil {
		if err := r.SetBodyParam(o.ConsentsRequest); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}