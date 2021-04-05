// Code generated by go-swagger; DO NOT EDIT.

package openbanking

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

	"github.com/cloudentity/acp-client-go/models"
)

// NewListDomesticScheduledPaymentConsentsParams creates a new ListDomesticScheduledPaymentConsentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListDomesticScheduledPaymentConsentsParams() *ListDomesticScheduledPaymentConsentsParams {
	return &ListDomesticScheduledPaymentConsentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListDomesticScheduledPaymentConsentsParamsWithTimeout creates a new ListDomesticScheduledPaymentConsentsParams object
// with the ability to set a timeout on a request.
func NewListDomesticScheduledPaymentConsentsParamsWithTimeout(timeout time.Duration) *ListDomesticScheduledPaymentConsentsParams {
	return &ListDomesticScheduledPaymentConsentsParams{
		timeout: timeout,
	}
}

// NewListDomesticScheduledPaymentConsentsParamsWithContext creates a new ListDomesticScheduledPaymentConsentsParams object
// with the ability to set a context for a request.
func NewListDomesticScheduledPaymentConsentsParamsWithContext(ctx context.Context) *ListDomesticScheduledPaymentConsentsParams {
	return &ListDomesticScheduledPaymentConsentsParams{
		Context: ctx,
	}
}

// NewListDomesticScheduledPaymentConsentsParamsWithHTTPClient creates a new ListDomesticScheduledPaymentConsentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListDomesticScheduledPaymentConsentsParamsWithHTTPClient(client *http.Client) *ListDomesticScheduledPaymentConsentsParams {
	return &ListDomesticScheduledPaymentConsentsParams{
		HTTPClient: client,
	}
}

/* ListDomesticScheduledPaymentConsentsParams contains all the parameters to send to the API endpoint
   for the list domestic scheduled payment consents operation.

   Typically these are written to a http.Request.
*/
type ListDomesticScheduledPaymentConsentsParams struct {

	// ListDomesticScheduledPaymentConsentsRequest.
	ListDomesticScheduledPaymentConsentsRequest *models.ListDomesticScheduledPaymentConsentsRequest

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

// WithDefaults hydrates default values in the list domestic scheduled payment consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListDomesticScheduledPaymentConsentsParams) WithDefaults() *ListDomesticScheduledPaymentConsentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list domestic scheduled payment consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListDomesticScheduledPaymentConsentsParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := ListDomesticScheduledPaymentConsentsParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithTimeout(timeout time.Duration) *ListDomesticScheduledPaymentConsentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithContext(ctx context.Context) *ListDomesticScheduledPaymentConsentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithHTTPClient(client *http.Client) *ListDomesticScheduledPaymentConsentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithListDomesticScheduledPaymentConsentsRequest adds the listDomesticScheduledPaymentConsentsRequest to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithListDomesticScheduledPaymentConsentsRequest(listDomesticScheduledPaymentConsentsRequest *models.ListDomesticScheduledPaymentConsentsRequest) *ListDomesticScheduledPaymentConsentsParams {
	o.SetListDomesticScheduledPaymentConsentsRequest(listDomesticScheduledPaymentConsentsRequest)
	return o
}

// SetListDomesticScheduledPaymentConsentsRequest adds the listDomesticScheduledPaymentConsentsRequest to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetListDomesticScheduledPaymentConsentsRequest(listDomesticScheduledPaymentConsentsRequest *models.ListDomesticScheduledPaymentConsentsRequest) {
	o.ListDomesticScheduledPaymentConsentsRequest = listDomesticScheduledPaymentConsentsRequest
}

// WithAid adds the aid to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithAid(aid string) *ListDomesticScheduledPaymentConsentsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) WithTid(tid string) *ListDomesticScheduledPaymentConsentsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list domestic scheduled payment consents params
func (o *ListDomesticScheduledPaymentConsentsParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ListDomesticScheduledPaymentConsentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ListDomesticScheduledPaymentConsentsRequest != nil {
		if err := r.SetBodyParam(o.ListDomesticScheduledPaymentConsentsRequest); err != nil {
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
