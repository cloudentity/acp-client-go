// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// RevokeOBBRConsentsReader is a Reader for the RevokeOBBRConsents structure.
type RevokeOBBRConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeOBBRConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeOBBRConsentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRevokeOBBRConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRevokeOBBRConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeOBBRConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeOBBRConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeOBBRConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRevokeOBBRConsentsOK creates a RevokeOBBRConsentsOK with default headers values
func NewRevokeOBBRConsentsOK() *RevokeOBBRConsentsOK {
	return &RevokeOBBRConsentsOK{}
}

/*
RevokeOBBRConsentsOK describes a response with status code 200, with default header values.

ConsentsRemovedResponse
*/
type RevokeOBBRConsentsOK struct {
	Payload *models.ConsentsRemovedResponse
}

// IsSuccess returns true when this revoke o b b r consents o k response has a 2xx status code
func (o *RevokeOBBRConsentsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke o b b r consents o k response has a 3xx status code
func (o *RevokeOBBRConsentsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents o k response has a 4xx status code
func (o *RevokeOBBRConsentsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke o b b r consents o k response has a 5xx status code
func (o *RevokeOBBRConsentsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents o k response a status code equal to that given
func (o *RevokeOBBRConsentsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the revoke o b b r consents o k response
func (o *RevokeOBBRConsentsOK) Code() int {
	return 200
}

func (o *RevokeOBBRConsentsOK) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsOK  %+v", 200, o.Payload)
}

func (o *RevokeOBBRConsentsOK) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsOK  %+v", 200, o.Payload)
}

func (o *RevokeOBBRConsentsOK) GetPayload() *models.ConsentsRemovedResponse {
	return o.Payload
}

func (o *RevokeOBBRConsentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentsRemovedResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeOBBRConsentsBadRequest creates a RevokeOBBRConsentsBadRequest with default headers values
func NewRevokeOBBRConsentsBadRequest() *RevokeOBBRConsentsBadRequest {
	return &RevokeOBBRConsentsBadRequest{}
}

/*
RevokeOBBRConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type RevokeOBBRConsentsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke o b b r consents bad request response has a 2xx status code
func (o *RevokeOBBRConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke o b b r consents bad request response has a 3xx status code
func (o *RevokeOBBRConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents bad request response has a 4xx status code
func (o *RevokeOBBRConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke o b b r consents bad request response has a 5xx status code
func (o *RevokeOBBRConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents bad request response a status code equal to that given
func (o *RevokeOBBRConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the revoke o b b r consents bad request response
func (o *RevokeOBBRConsentsBadRequest) Code() int {
	return 400
}

func (o *RevokeOBBRConsentsBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *RevokeOBBRConsentsBadRequest) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *RevokeOBBRConsentsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeOBBRConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeOBBRConsentsUnauthorized creates a RevokeOBBRConsentsUnauthorized with default headers values
func NewRevokeOBBRConsentsUnauthorized() *RevokeOBBRConsentsUnauthorized {
	return &RevokeOBBRConsentsUnauthorized{}
}

/*
RevokeOBBRConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeOBBRConsentsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke o b b r consents unauthorized response has a 2xx status code
func (o *RevokeOBBRConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke o b b r consents unauthorized response has a 3xx status code
func (o *RevokeOBBRConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents unauthorized response has a 4xx status code
func (o *RevokeOBBRConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke o b b r consents unauthorized response has a 5xx status code
func (o *RevokeOBBRConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents unauthorized response a status code equal to that given
func (o *RevokeOBBRConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke o b b r consents unauthorized response
func (o *RevokeOBBRConsentsUnauthorized) Code() int {
	return 401
}

func (o *RevokeOBBRConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeOBBRConsentsUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeOBBRConsentsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeOBBRConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeOBBRConsentsForbidden creates a RevokeOBBRConsentsForbidden with default headers values
func NewRevokeOBBRConsentsForbidden() *RevokeOBBRConsentsForbidden {
	return &RevokeOBBRConsentsForbidden{}
}

/*
RevokeOBBRConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeOBBRConsentsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke o b b r consents forbidden response has a 2xx status code
func (o *RevokeOBBRConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke o b b r consents forbidden response has a 3xx status code
func (o *RevokeOBBRConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents forbidden response has a 4xx status code
func (o *RevokeOBBRConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke o b b r consents forbidden response has a 5xx status code
func (o *RevokeOBBRConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents forbidden response a status code equal to that given
func (o *RevokeOBBRConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke o b b r consents forbidden response
func (o *RevokeOBBRConsentsForbidden) Code() int {
	return 403
}

func (o *RevokeOBBRConsentsForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsForbidden  %+v", 403, o.Payload)
}

func (o *RevokeOBBRConsentsForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsForbidden  %+v", 403, o.Payload)
}

func (o *RevokeOBBRConsentsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeOBBRConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeOBBRConsentsNotFound creates a RevokeOBBRConsentsNotFound with default headers values
func NewRevokeOBBRConsentsNotFound() *RevokeOBBRConsentsNotFound {
	return &RevokeOBBRConsentsNotFound{}
}

/*
RevokeOBBRConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type RevokeOBBRConsentsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke o b b r consents not found response has a 2xx status code
func (o *RevokeOBBRConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke o b b r consents not found response has a 3xx status code
func (o *RevokeOBBRConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents not found response has a 4xx status code
func (o *RevokeOBBRConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke o b b r consents not found response has a 5xx status code
func (o *RevokeOBBRConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents not found response a status code equal to that given
func (o *RevokeOBBRConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke o b b r consents not found response
func (o *RevokeOBBRConsentsNotFound) Code() int {
	return 404
}

func (o *RevokeOBBRConsentsNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsNotFound  %+v", 404, o.Payload)
}

func (o *RevokeOBBRConsentsNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsNotFound  %+v", 404, o.Payload)
}

func (o *RevokeOBBRConsentsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeOBBRConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeOBBRConsentsTooManyRequests creates a RevokeOBBRConsentsTooManyRequests with default headers values
func NewRevokeOBBRConsentsTooManyRequests() *RevokeOBBRConsentsTooManyRequests {
	return &RevokeOBBRConsentsTooManyRequests{}
}

/*
RevokeOBBRConsentsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RevokeOBBRConsentsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke o b b r consents too many requests response has a 2xx status code
func (o *RevokeOBBRConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke o b b r consents too many requests response has a 3xx status code
func (o *RevokeOBBRConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o b b r consents too many requests response has a 4xx status code
func (o *RevokeOBBRConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke o b b r consents too many requests response has a 5xx status code
func (o *RevokeOBBRConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o b b r consents too many requests response a status code equal to that given
func (o *RevokeOBBRConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the revoke o b b r consents too many requests response
func (o *RevokeOBBRConsentsTooManyRequests) Code() int {
	return 429
}

func (o *RevokeOBBRConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeOBBRConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/open-banking-brasil/consents][%d] revokeOBBRConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeOBBRConsentsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeOBBRConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
