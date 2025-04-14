// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// SetServerConsentReader is a Reader for the SetServerConsent structure.
type SetServerConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetServerConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetServerConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSetServerConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetServerConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetServerConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetServerConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/server-consent] setServerConsent", response, response.Code())
	}
}

// NewSetServerConsentOK creates a SetServerConsentOK with default headers values
func NewSetServerConsentOK() *SetServerConsentOK {
	return &SetServerConsentOK{}
}

/*
SetServerConsentOK describes a response with status code 200, with default header values.

ServerConsent
*/
type SetServerConsentOK struct {
	Payload *models.ServerConsent
}

// IsSuccess returns true when this set server consent o k response has a 2xx status code
func (o *SetServerConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set server consent o k response has a 3xx status code
func (o *SetServerConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set server consent o k response has a 4xx status code
func (o *SetServerConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this set server consent o k response has a 5xx status code
func (o *SetServerConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this set server consent o k response a status code equal to that given
func (o *SetServerConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the set server consent o k response
func (o *SetServerConsentOK) Code() int {
	return 200
}

func (o *SetServerConsentOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentOK  %+v", 200, o.Payload)
}

func (o *SetServerConsentOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentOK  %+v", 200, o.Payload)
}

func (o *SetServerConsentOK) GetPayload() *models.ServerConsent {
	return o.Payload
}

func (o *SetServerConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ServerConsent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetServerConsentUnauthorized creates a SetServerConsentUnauthorized with default headers values
func NewSetServerConsentUnauthorized() *SetServerConsentUnauthorized {
	return &SetServerConsentUnauthorized{}
}

/*
SetServerConsentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetServerConsentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set server consent unauthorized response has a 2xx status code
func (o *SetServerConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set server consent unauthorized response has a 3xx status code
func (o *SetServerConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set server consent unauthorized response has a 4xx status code
func (o *SetServerConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set server consent unauthorized response has a 5xx status code
func (o *SetServerConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set server consent unauthorized response a status code equal to that given
func (o *SetServerConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set server consent unauthorized response
func (o *SetServerConsentUnauthorized) Code() int {
	return 401
}

func (o *SetServerConsentUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *SetServerConsentUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *SetServerConsentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetServerConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetServerConsentForbidden creates a SetServerConsentForbidden with default headers values
func NewSetServerConsentForbidden() *SetServerConsentForbidden {
	return &SetServerConsentForbidden{}
}

/*
SetServerConsentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetServerConsentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set server consent forbidden response has a 2xx status code
func (o *SetServerConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set server consent forbidden response has a 3xx status code
func (o *SetServerConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set server consent forbidden response has a 4xx status code
func (o *SetServerConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set server consent forbidden response has a 5xx status code
func (o *SetServerConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set server consent forbidden response a status code equal to that given
func (o *SetServerConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set server consent forbidden response
func (o *SetServerConsentForbidden) Code() int {
	return 403
}

func (o *SetServerConsentForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentForbidden  %+v", 403, o.Payload)
}

func (o *SetServerConsentForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentForbidden  %+v", 403, o.Payload)
}

func (o *SetServerConsentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetServerConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetServerConsentNotFound creates a SetServerConsentNotFound with default headers values
func NewSetServerConsentNotFound() *SetServerConsentNotFound {
	return &SetServerConsentNotFound{}
}

/*
SetServerConsentNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetServerConsentNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set server consent not found response has a 2xx status code
func (o *SetServerConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set server consent not found response has a 3xx status code
func (o *SetServerConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set server consent not found response has a 4xx status code
func (o *SetServerConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set server consent not found response has a 5xx status code
func (o *SetServerConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set server consent not found response a status code equal to that given
func (o *SetServerConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set server consent not found response
func (o *SetServerConsentNotFound) Code() int {
	return 404
}

func (o *SetServerConsentNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentNotFound  %+v", 404, o.Payload)
}

func (o *SetServerConsentNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentNotFound  %+v", 404, o.Payload)
}

func (o *SetServerConsentNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetServerConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetServerConsentTooManyRequests creates a SetServerConsentTooManyRequests with default headers values
func NewSetServerConsentTooManyRequests() *SetServerConsentTooManyRequests {
	return &SetServerConsentTooManyRequests{}
}

/*
SetServerConsentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SetServerConsentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set server consent too many requests response has a 2xx status code
func (o *SetServerConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set server consent too many requests response has a 3xx status code
func (o *SetServerConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set server consent too many requests response has a 4xx status code
func (o *SetServerConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set server consent too many requests response has a 5xx status code
func (o *SetServerConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set server consent too many requests response a status code equal to that given
func (o *SetServerConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set server consent too many requests response
func (o *SetServerConsentTooManyRequests) Code() int {
	return 429
}

func (o *SetServerConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetServerConsentTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/server-consent][%d] setServerConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetServerConsentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetServerConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
