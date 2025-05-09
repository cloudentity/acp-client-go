// Code generated by go-swagger; DO NOT EDIT.

package translations

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

// NewGetTranslationParams creates a new GetTranslationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTranslationParams() *GetTranslationParams {
	return &GetTranslationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTranslationParamsWithTimeout creates a new GetTranslationParams object
// with the ability to set a timeout on a request.
func NewGetTranslationParamsWithTimeout(timeout time.Duration) *GetTranslationParams {
	return &GetTranslationParams{
		timeout: timeout,
	}
}

// NewGetTranslationParamsWithContext creates a new GetTranslationParams object
// with the ability to set a context for a request.
func NewGetTranslationParamsWithContext(ctx context.Context) *GetTranslationParams {
	return &GetTranslationParams{
		Context: ctx,
	}
}

// NewGetTranslationParamsWithHTTPClient creates a new GetTranslationParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTranslationParamsWithHTTPClient(client *http.Client) *GetTranslationParams {
	return &GetTranslationParams{
		HTTPClient: client,
	}
}

/*
GetTranslationParams contains all the parameters to send to the API endpoint

	for the get translation operation.

	Typically these are written to a http.Request.
*/
type GetTranslationParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Locale.

	   translation locale
	*/
	Locale string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get translation params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTranslationParams) WithDefaults() *GetTranslationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get translation params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTranslationParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get translation params
func (o *GetTranslationParams) WithTimeout(timeout time.Duration) *GetTranslationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get translation params
func (o *GetTranslationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get translation params
func (o *GetTranslationParams) WithContext(ctx context.Context) *GetTranslationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get translation params
func (o *GetTranslationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get translation params
func (o *GetTranslationParams) WithHTTPClient(client *http.Client) *GetTranslationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get translation params
func (o *GetTranslationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get translation params
func (o *GetTranslationParams) WithIfMatch(ifMatch *string) *GetTranslationParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get translation params
func (o *GetTranslationParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithLocale adds the locale to the get translation params
func (o *GetTranslationParams) WithLocale(locale string) *GetTranslationParams {
	o.SetLocale(locale)
	return o
}

// SetLocale adds the locale to the get translation params
func (o *GetTranslationParams) SetLocale(locale string) {
	o.Locale = locale
}

// WriteToRequest writes these params to a swagger request
func (o *GetTranslationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param locale
	if err := r.SetPathParam("locale", o.Locale); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
