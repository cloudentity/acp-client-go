// Code generated by go-swagger; DO NOT EDIT.

package users

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

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// NewSystemDeleteVerifiableAddressParams creates a new SystemDeleteVerifiableAddressParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSystemDeleteVerifiableAddressParams() *SystemDeleteVerifiableAddressParams {
	return &SystemDeleteVerifiableAddressParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSystemDeleteVerifiableAddressParamsWithTimeout creates a new SystemDeleteVerifiableAddressParams object
// with the ability to set a timeout on a request.
func NewSystemDeleteVerifiableAddressParamsWithTimeout(timeout time.Duration) *SystemDeleteVerifiableAddressParams {
	return &SystemDeleteVerifiableAddressParams{
		timeout: timeout,
	}
}

// NewSystemDeleteVerifiableAddressParamsWithContext creates a new SystemDeleteVerifiableAddressParams object
// with the ability to set a context for a request.
func NewSystemDeleteVerifiableAddressParamsWithContext(ctx context.Context) *SystemDeleteVerifiableAddressParams {
	return &SystemDeleteVerifiableAddressParams{
		Context: ctx,
	}
}

// NewSystemDeleteVerifiableAddressParamsWithHTTPClient creates a new SystemDeleteVerifiableAddressParams object
// with the ability to set a custom HTTPClient for a request.
func NewSystemDeleteVerifiableAddressParamsWithHTTPClient(client *http.Client) *SystemDeleteVerifiableAddressParams {
	return &SystemDeleteVerifiableAddressParams{
		HTTPClient: client,
	}
}

/*
SystemDeleteVerifiableAddressParams contains all the parameters to send to the API endpoint

	for the system delete verifiable address operation.

	Typically these are written to a http.Request.
*/
type SystemDeleteVerifiableAddressParams struct {

	// Address.
	Address *models.DeleteUserVerifiableAddress

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the system delete verifiable address params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemDeleteVerifiableAddressParams) WithDefaults() *SystemDeleteVerifiableAddressParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the system delete verifiable address params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemDeleteVerifiableAddressParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithTimeout(timeout time.Duration) *SystemDeleteVerifiableAddressParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithContext(ctx context.Context) *SystemDeleteVerifiableAddressParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithHTTPClient(client *http.Client) *SystemDeleteVerifiableAddressParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAddress adds the address to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithAddress(address *models.DeleteUserVerifiableAddress) *SystemDeleteVerifiableAddressParams {
	o.SetAddress(address)
	return o
}

// SetAddress adds the address to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetAddress(address *models.DeleteUserVerifiableAddress) {
	o.Address = address
}

// WithIfMatch adds the ifMatch to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithIfMatch(ifMatch *string) *SystemDeleteVerifiableAddressParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithIPID(iPID string) *SystemDeleteVerifiableAddressParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) WithUserID(userID string) *SystemDeleteVerifiableAddressParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the system delete verifiable address params
func (o *SystemDeleteVerifiableAddressParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *SystemDeleteVerifiableAddressParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Address != nil {
		if err := r.SetBodyParam(o.Address); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}