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
)

// NewRevokeCDRArrangementByIDParams creates a new RevokeCDRArrangementByIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeCDRArrangementByIDParams() *RevokeCDRArrangementByIDParams {
	return &RevokeCDRArrangementByIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeCDRArrangementByIDParamsWithTimeout creates a new RevokeCDRArrangementByIDParams object
// with the ability to set a timeout on a request.
func NewRevokeCDRArrangementByIDParamsWithTimeout(timeout time.Duration) *RevokeCDRArrangementByIDParams {
	return &RevokeCDRArrangementByIDParams{
		timeout: timeout,
	}
}

// NewRevokeCDRArrangementByIDParamsWithContext creates a new RevokeCDRArrangementByIDParams object
// with the ability to set a context for a request.
func NewRevokeCDRArrangementByIDParamsWithContext(ctx context.Context) *RevokeCDRArrangementByIDParams {
	return &RevokeCDRArrangementByIDParams{
		Context: ctx,
	}
}

// NewRevokeCDRArrangementByIDParamsWithHTTPClient creates a new RevokeCDRArrangementByIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeCDRArrangementByIDParamsWithHTTPClient(client *http.Client) *RevokeCDRArrangementByIDParams {
	return &RevokeCDRArrangementByIDParams{
		HTTPClient: client,
	}
}

/*
RevokeCDRArrangementByIDParams contains all the parameters to send to the API endpoint

	for the revoke c d r arrangement by ID operation.

	Typically these are written to a http.Request.
*/
type RevokeCDRArrangementByIDParams struct {

	/* ArrangementID.

	   Arrangement id
	*/
	ArrangementID string

	// RevocationChannel.
	//
	// Default: "online"
	RevocationChannel *string

	/* RevocationReason.

	   Stores the reason why the arrangement was revoked
	*/
	RevocationReason *string

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the revoke c d r arrangement by ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeCDRArrangementByIDParams) WithDefaults() *RevokeCDRArrangementByIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke c d r arrangement by ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeCDRArrangementByIDParams) SetDefaults() {
	var (
		revocationChannelDefault = string("online")

		widDefault = string("default")
	)

	val := RevokeCDRArrangementByIDParams{
		RevocationChannel: &revocationChannelDefault,
		Wid:               widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithTimeout(timeout time.Duration) *RevokeCDRArrangementByIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithContext(ctx context.Context) *RevokeCDRArrangementByIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithHTTPClient(client *http.Client) *RevokeCDRArrangementByIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithArrangementID adds the arrangementID to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithArrangementID(arrangementID string) *RevokeCDRArrangementByIDParams {
	o.SetArrangementID(arrangementID)
	return o
}

// SetArrangementID adds the arrangementId to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetArrangementID(arrangementID string) {
	o.ArrangementID = arrangementID
}

// WithRevocationChannel adds the revocationChannel to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithRevocationChannel(revocationChannel *string) *RevokeCDRArrangementByIDParams {
	o.SetRevocationChannel(revocationChannel)
	return o
}

// SetRevocationChannel adds the revocationChannel to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetRevocationChannel(revocationChannel *string) {
	o.RevocationChannel = revocationChannel
}

// WithRevocationReason adds the revocationReason to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithRevocationReason(revocationReason *string) *RevokeCDRArrangementByIDParams {
	o.SetRevocationReason(revocationReason)
	return o
}

// SetRevocationReason adds the revocationReason to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetRevocationReason(revocationReason *string) {
	o.RevocationReason = revocationReason
}

// WithWid adds the wid to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) WithWid(wid string) *RevokeCDRArrangementByIDParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the revoke c d r arrangement by ID params
func (o *RevokeCDRArrangementByIDParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeCDRArrangementByIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param arrangementID
	if err := r.SetPathParam("arrangementID", o.ArrangementID); err != nil {
		return err
	}

	if o.RevocationChannel != nil {

		// query param revocation_channel
		var qrRevocationChannel string

		if o.RevocationChannel != nil {
			qrRevocationChannel = *o.RevocationChannel
		}
		qRevocationChannel := qrRevocationChannel
		if qRevocationChannel != "" {

			if err := r.SetQueryParam("revocation_channel", qRevocationChannel); err != nil {
				return err
			}
		}
	}

	if o.RevocationReason != nil {

		// query param revocation_reason
		var qrRevocationReason string

		if o.RevocationReason != nil {
			qrRevocationReason = *o.RevocationReason
		}
		qRevocationReason := qrRevocationReason
		if qRevocationReason != "" {

			if err := r.SetQueryParam("revocation_reason", qRevocationReason); err != nil {
				return err
			}
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
