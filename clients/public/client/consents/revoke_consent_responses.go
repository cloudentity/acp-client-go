// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/public/models"
)

// RevokeConsentReader is a Reader for the RevokeConsent structure.
type RevokeConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRevokeConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /privacy/consents/revoke] revokeConsent", response, response.Code())
	}
}

// NewRevokeConsentOK creates a RevokeConsentOK with default headers values
func NewRevokeConsentOK() *RevokeConsentOK {
	return &RevokeConsentOK{}
}

/*
RevokeConsentOK describes a response with status code 200, with default header values.

Consent grant
*/
type RevokeConsentOK struct {
	Payload *models.ConsentGrant
}

// IsSuccess returns true when this revoke consent o k response has a 2xx status code
func (o *RevokeConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke consent o k response has a 3xx status code
func (o *RevokeConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent o k response has a 4xx status code
func (o *RevokeConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke consent o k response has a 5xx status code
func (o *RevokeConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent o k response a status code equal to that given
func (o *RevokeConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the revoke consent o k response
func (o *RevokeConsentOK) Code() int {
	return 200
}

func (o *RevokeConsentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentOK %s", 200, payload)
}

func (o *RevokeConsentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentOK %s", 200, payload)
}

func (o *RevokeConsentOK) GetPayload() *models.ConsentGrant {
	return o.Payload
}

func (o *RevokeConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentGrant)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeConsentUnauthorized creates a RevokeConsentUnauthorized with default headers values
func NewRevokeConsentUnauthorized() *RevokeConsentUnauthorized {
	return &RevokeConsentUnauthorized{}
}

/*
RevokeConsentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeConsentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke consent unauthorized response has a 2xx status code
func (o *RevokeConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke consent unauthorized response has a 3xx status code
func (o *RevokeConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent unauthorized response has a 4xx status code
func (o *RevokeConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke consent unauthorized response has a 5xx status code
func (o *RevokeConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent unauthorized response a status code equal to that given
func (o *RevokeConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke consent unauthorized response
func (o *RevokeConsentUnauthorized) Code() int {
	return 401
}

func (o *RevokeConsentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentUnauthorized %s", 401, payload)
}

func (o *RevokeConsentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentUnauthorized %s", 401, payload)
}

func (o *RevokeConsentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeConsentForbidden creates a RevokeConsentForbidden with default headers values
func NewRevokeConsentForbidden() *RevokeConsentForbidden {
	return &RevokeConsentForbidden{}
}

/*
RevokeConsentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeConsentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke consent forbidden response has a 2xx status code
func (o *RevokeConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke consent forbidden response has a 3xx status code
func (o *RevokeConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent forbidden response has a 4xx status code
func (o *RevokeConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke consent forbidden response has a 5xx status code
func (o *RevokeConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent forbidden response a status code equal to that given
func (o *RevokeConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke consent forbidden response
func (o *RevokeConsentForbidden) Code() int {
	return 403
}

func (o *RevokeConsentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentForbidden %s", 403, payload)
}

func (o *RevokeConsentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentForbidden %s", 403, payload)
}

func (o *RevokeConsentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeConsentNotFound creates a RevokeConsentNotFound with default headers values
func NewRevokeConsentNotFound() *RevokeConsentNotFound {
	return &RevokeConsentNotFound{}
}

/*
RevokeConsentNotFound describes a response with status code 404, with default header values.

Not found
*/
type RevokeConsentNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke consent not found response has a 2xx status code
func (o *RevokeConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke consent not found response has a 3xx status code
func (o *RevokeConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent not found response has a 4xx status code
func (o *RevokeConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke consent not found response has a 5xx status code
func (o *RevokeConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent not found response a status code equal to that given
func (o *RevokeConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke consent not found response
func (o *RevokeConsentNotFound) Code() int {
	return 404
}

func (o *RevokeConsentNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentNotFound %s", 404, payload)
}

func (o *RevokeConsentNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentNotFound %s", 404, payload)
}

func (o *RevokeConsentNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeConsentUnprocessableEntity creates a RevokeConsentUnprocessableEntity with default headers values
func NewRevokeConsentUnprocessableEntity() *RevokeConsentUnprocessableEntity {
	return &RevokeConsentUnprocessableEntity{}
}

/*
RevokeConsentUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type RevokeConsentUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke consent unprocessable entity response has a 2xx status code
func (o *RevokeConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke consent unprocessable entity response has a 3xx status code
func (o *RevokeConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent unprocessable entity response has a 4xx status code
func (o *RevokeConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke consent unprocessable entity response has a 5xx status code
func (o *RevokeConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent unprocessable entity response a status code equal to that given
func (o *RevokeConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the revoke consent unprocessable entity response
func (o *RevokeConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *RevokeConsentUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentUnprocessableEntity %s", 422, payload)
}

func (o *RevokeConsentUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentUnprocessableEntity %s", 422, payload)
}

func (o *RevokeConsentUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeConsentTooManyRequests creates a RevokeConsentTooManyRequests with default headers values
func NewRevokeConsentTooManyRequests() *RevokeConsentTooManyRequests {
	return &RevokeConsentTooManyRequests{}
}

/*
RevokeConsentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RevokeConsentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke consent too many requests response has a 2xx status code
func (o *RevokeConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke consent too many requests response has a 3xx status code
func (o *RevokeConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke consent too many requests response has a 4xx status code
func (o *RevokeConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke consent too many requests response has a 5xx status code
func (o *RevokeConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke consent too many requests response a status code equal to that given
func (o *RevokeConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the revoke consent too many requests response
func (o *RevokeConsentTooManyRequests) Code() int {
	return 429
}

func (o *RevokeConsentTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentTooManyRequests %s", 429, payload)
}

func (o *RevokeConsentTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /privacy/consents/revoke][%d] revokeConsentTooManyRequests %s", 429, payload)
}

func (o *RevokeConsentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
