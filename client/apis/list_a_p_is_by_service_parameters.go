// Code generated by go-swagger; DO NOT EDIT.

package apis

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
	"github.com/go-openapi/swag"
)

// NewListAPIsByServiceParams creates a new ListAPIsByServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListAPIsByServiceParams() *ListAPIsByServiceParams {
	return &ListAPIsByServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListAPIsByServiceParamsWithTimeout creates a new ListAPIsByServiceParams object
// with the ability to set a timeout on a request.
func NewListAPIsByServiceParamsWithTimeout(timeout time.Duration) *ListAPIsByServiceParams {
	return &ListAPIsByServiceParams{
		timeout: timeout,
	}
}

// NewListAPIsByServiceParamsWithContext creates a new ListAPIsByServiceParams object
// with the ability to set a context for a request.
func NewListAPIsByServiceParamsWithContext(ctx context.Context) *ListAPIsByServiceParams {
	return &ListAPIsByServiceParams{
		Context: ctx,
	}
}

// NewListAPIsByServiceParamsWithHTTPClient creates a new ListAPIsByServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewListAPIsByServiceParamsWithHTTPClient(client *http.Client) *ListAPIsByServiceParams {
	return &ListAPIsByServiceParams{
		HTTPClient: client,
	}
}

/* ListAPIsByServiceParams contains all the parameters to send to the API endpoint
   for the list a p is by service operation.

   Typically these are written to a http.Request.
*/
type ListAPIsByServiceParams struct {

	/* DataClassification.

	   List apis that have given data classifications
	*/
	DataClassification []string

	/* Sid.

	   Service id

	   Default: "default"
	*/
	Sid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	/* WithoutDataClassifications.

	   List apis that have no data classifications
	*/
	WithoutDataClassifications *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list a p is by service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAPIsByServiceParams) WithDefaults() *ListAPIsByServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list a p is by service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAPIsByServiceParams) SetDefaults() {
	var (
		sidDefault = string("default")

		tidDefault = string("default")
	)

	val := ListAPIsByServiceParams{
		Sid: sidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list a p is by service params
func (o *ListAPIsByServiceParams) WithTimeout(timeout time.Duration) *ListAPIsByServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list a p is by service params
func (o *ListAPIsByServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list a p is by service params
func (o *ListAPIsByServiceParams) WithContext(ctx context.Context) *ListAPIsByServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list a p is by service params
func (o *ListAPIsByServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list a p is by service params
func (o *ListAPIsByServiceParams) WithHTTPClient(client *http.Client) *ListAPIsByServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list a p is by service params
func (o *ListAPIsByServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDataClassification adds the dataClassification to the list a p is by service params
func (o *ListAPIsByServiceParams) WithDataClassification(dataClassification []string) *ListAPIsByServiceParams {
	o.SetDataClassification(dataClassification)
	return o
}

// SetDataClassification adds the dataClassification to the list a p is by service params
func (o *ListAPIsByServiceParams) SetDataClassification(dataClassification []string) {
	o.DataClassification = dataClassification
}

// WithSid adds the sid to the list a p is by service params
func (o *ListAPIsByServiceParams) WithSid(sid string) *ListAPIsByServiceParams {
	o.SetSid(sid)
	return o
}

// SetSid adds the sid to the list a p is by service params
func (o *ListAPIsByServiceParams) SetSid(sid string) {
	o.Sid = sid
}

// WithTid adds the tid to the list a p is by service params
func (o *ListAPIsByServiceParams) WithTid(tid string) *ListAPIsByServiceParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list a p is by service params
func (o *ListAPIsByServiceParams) SetTid(tid string) {
	o.Tid = tid
}

// WithWithoutDataClassifications adds the withoutDataClassifications to the list a p is by service params
func (o *ListAPIsByServiceParams) WithWithoutDataClassifications(withoutDataClassifications *bool) *ListAPIsByServiceParams {
	o.SetWithoutDataClassifications(withoutDataClassifications)
	return o
}

// SetWithoutDataClassifications adds the withoutDataClassifications to the list a p is by service params
func (o *ListAPIsByServiceParams) SetWithoutDataClassifications(withoutDataClassifications *bool) {
	o.WithoutDataClassifications = withoutDataClassifications
}

// WriteToRequest writes these params to a swagger request
func (o *ListAPIsByServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.DataClassification != nil {

		// binding items for data_classification
		joinedDataClassification := o.bindParamDataClassification(reg)

		// query array param data_classification
		if err := r.SetQueryParam("data_classification", joinedDataClassification...); err != nil {
			return err
		}
	}

	// path param sid
	if err := r.SetPathParam("sid", o.Sid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if o.WithoutDataClassifications != nil {

		// query param without_data_classifications
		var qrWithoutDataClassifications bool

		if o.WithoutDataClassifications != nil {
			qrWithoutDataClassifications = *o.WithoutDataClassifications
		}
		qWithoutDataClassifications := swag.FormatBool(qrWithoutDataClassifications)
		if qWithoutDataClassifications != "" {

			if err := r.SetQueryParam("without_data_classifications", qWithoutDataClassifications); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamListAPIsByService binds the parameter data_classification
func (o *ListAPIsByServiceParams) bindParamDataClassification(formats strfmt.Registry) []string {
	dataClassificationIR := o.DataClassification

	var dataClassificationIC []string
	for _, dataClassificationIIR := range dataClassificationIR { // explode []string

		dataClassificationIIV := dataClassificationIIR // string as string
		dataClassificationIC = append(dataClassificationIC, dataClassificationIIV)
	}

	// items.CollectionFormat: ""
	dataClassificationIS := swag.JoinByFormat(dataClassificationIC, "")

	return dataClassificationIS
}
