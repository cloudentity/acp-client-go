// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewImportSAMLMetadataFromURLParams creates a new ImportSAMLMetadataFromURLParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewImportSAMLMetadataFromURLParams() *ImportSAMLMetadataFromURLParams {
	return &ImportSAMLMetadataFromURLParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewImportSAMLMetadataFromURLParamsWithTimeout creates a new ImportSAMLMetadataFromURLParams object
// with the ability to set a timeout on a request.
func NewImportSAMLMetadataFromURLParamsWithTimeout(timeout time.Duration) *ImportSAMLMetadataFromURLParams {
	return &ImportSAMLMetadataFromURLParams{
		timeout: timeout,
	}
}

// NewImportSAMLMetadataFromURLParamsWithContext creates a new ImportSAMLMetadataFromURLParams object
// with the ability to set a context for a request.
func NewImportSAMLMetadataFromURLParamsWithContext(ctx context.Context) *ImportSAMLMetadataFromURLParams {
	return &ImportSAMLMetadataFromURLParams{
		Context: ctx,
	}
}

// NewImportSAMLMetadataFromURLParamsWithHTTPClient creates a new ImportSAMLMetadataFromURLParams object
// with the ability to set a custom HTTPClient for a request.
func NewImportSAMLMetadataFromURLParamsWithHTTPClient(client *http.Client) *ImportSAMLMetadataFromURLParams {
	return &ImportSAMLMetadataFromURLParams{
		HTTPClient: client,
	}
}

/*
ImportSAMLMetadataFromURLParams contains all the parameters to send to the API endpoint

	for the import s a m l metadata from URL operation.

	Typically these are written to a http.Request.
*/
type ImportSAMLMetadataFromURLParams struct {

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// URL.
	URL *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the import s a m l metadata from URL params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportSAMLMetadataFromURLParams) WithDefaults() *ImportSAMLMetadataFromURLParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the import s a m l metadata from URL params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportSAMLMetadataFromURLParams) SetDefaults() {
	var (
		cidDefault = string("default")
	)

	val := ImportSAMLMetadataFromURLParams{
		Cid: cidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithTimeout(timeout time.Duration) *ImportSAMLMetadataFromURLParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithContext(ctx context.Context) *ImportSAMLMetadataFromURLParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithHTTPClient(client *http.Client) *ImportSAMLMetadataFromURLParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCid adds the cid to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithCid(cid string) *ImportSAMLMetadataFromURLParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetCid(cid string) {
	o.Cid = cid
}

// WithIfMatch adds the ifMatch to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithIfMatch(ifMatch *string) *ImportSAMLMetadataFromURLParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithURL adds the url to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) WithURL(url *string) *ImportSAMLMetadataFromURLParams {
	o.SetURL(url)
	return o
}

// SetURL adds the url to the import s a m l metadata from URL params
func (o *ImportSAMLMetadataFromURLParams) SetURL(url *string) {
	o.URL = url
}

// WriteToRequest writes these params to a swagger request
func (o *ImportSAMLMetadataFromURLParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
		return err
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if o.URL != nil {

		// form param url
		var frURL string
		if o.URL != nil {
			frURL = *o.URL
		}
		fURL := frURL
		if fURL != "" {
			if err := r.SetFormParam("url", fURL); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
