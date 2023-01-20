// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemDeleteIdentifierReader is a Reader for the SystemDeleteIdentifier structure.
type SystemDeleteIdentifierReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemDeleteIdentifierReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSystemDeleteIdentifierNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemDeleteIdentifierUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemDeleteIdentifierForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemDeleteIdentifierNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemDeleteIdentifierPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemDeleteIdentifierTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemDeleteIdentifierNoContent creates a SystemDeleteIdentifierNoContent with default headers values
func NewSystemDeleteIdentifierNoContent() *SystemDeleteIdentifierNoContent {
	return &SystemDeleteIdentifierNoContent{}
}

/*
SystemDeleteIdentifierNoContent describes a response with status code 204, with default header values.

Deletes an identifier from the user account
*/
type SystemDeleteIdentifierNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this system delete identifier no content response has a 2xx status code
func (o *SystemDeleteIdentifierNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system delete identifier no content response has a 3xx status code
func (o *SystemDeleteIdentifierNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier no content response has a 4xx status code
func (o *SystemDeleteIdentifierNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this system delete identifier no content response has a 5xx status code
func (o *SystemDeleteIdentifierNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier no content response a status code equal to that given
func (o *SystemDeleteIdentifierNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *SystemDeleteIdentifierNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierNoContent ", 204)
}

func (o *SystemDeleteIdentifierNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierNoContent ", 204)
}

func (o *SystemDeleteIdentifierNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewSystemDeleteIdentifierUnauthorized creates a SystemDeleteIdentifierUnauthorized with default headers values
func NewSystemDeleteIdentifierUnauthorized() *SystemDeleteIdentifierUnauthorized {
	return &SystemDeleteIdentifierUnauthorized{}
}

/*
SystemDeleteIdentifierUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemDeleteIdentifierUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete identifier unauthorized response has a 2xx status code
func (o *SystemDeleteIdentifierUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete identifier unauthorized response has a 3xx status code
func (o *SystemDeleteIdentifierUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier unauthorized response has a 4xx status code
func (o *SystemDeleteIdentifierUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete identifier unauthorized response has a 5xx status code
func (o *SystemDeleteIdentifierUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier unauthorized response a status code equal to that given
func (o *SystemDeleteIdentifierUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemDeleteIdentifierUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteIdentifierUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteIdentifierUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteIdentifierUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteIdentifierForbidden creates a SystemDeleteIdentifierForbidden with default headers values
func NewSystemDeleteIdentifierForbidden() *SystemDeleteIdentifierForbidden {
	return &SystemDeleteIdentifierForbidden{}
}

/*
SystemDeleteIdentifierForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemDeleteIdentifierForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete identifier forbidden response has a 2xx status code
func (o *SystemDeleteIdentifierForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete identifier forbidden response has a 3xx status code
func (o *SystemDeleteIdentifierForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier forbidden response has a 4xx status code
func (o *SystemDeleteIdentifierForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete identifier forbidden response has a 5xx status code
func (o *SystemDeleteIdentifierForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier forbidden response a status code equal to that given
func (o *SystemDeleteIdentifierForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemDeleteIdentifierForbidden) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteIdentifierForbidden) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteIdentifierForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteIdentifierForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteIdentifierNotFound creates a SystemDeleteIdentifierNotFound with default headers values
func NewSystemDeleteIdentifierNotFound() *SystemDeleteIdentifierNotFound {
	return &SystemDeleteIdentifierNotFound{}
}

/*
SystemDeleteIdentifierNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemDeleteIdentifierNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete identifier not found response has a 2xx status code
func (o *SystemDeleteIdentifierNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete identifier not found response has a 3xx status code
func (o *SystemDeleteIdentifierNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier not found response has a 4xx status code
func (o *SystemDeleteIdentifierNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete identifier not found response has a 5xx status code
func (o *SystemDeleteIdentifierNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier not found response a status code equal to that given
func (o *SystemDeleteIdentifierNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemDeleteIdentifierNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteIdentifierNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteIdentifierNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteIdentifierNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteIdentifierPreconditionFailed creates a SystemDeleteIdentifierPreconditionFailed with default headers values
func NewSystemDeleteIdentifierPreconditionFailed() *SystemDeleteIdentifierPreconditionFailed {
	return &SystemDeleteIdentifierPreconditionFailed{}
}

/*
SystemDeleteIdentifierPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type SystemDeleteIdentifierPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete identifier precondition failed response has a 2xx status code
func (o *SystemDeleteIdentifierPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete identifier precondition failed response has a 3xx status code
func (o *SystemDeleteIdentifierPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier precondition failed response has a 4xx status code
func (o *SystemDeleteIdentifierPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete identifier precondition failed response has a 5xx status code
func (o *SystemDeleteIdentifierPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier precondition failed response a status code equal to that given
func (o *SystemDeleteIdentifierPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemDeleteIdentifierPreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteIdentifierPreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteIdentifierPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteIdentifierPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteIdentifierTooManyRequests creates a SystemDeleteIdentifierTooManyRequests with default headers values
func NewSystemDeleteIdentifierTooManyRequests() *SystemDeleteIdentifierTooManyRequests {
	return &SystemDeleteIdentifierTooManyRequests{}
}

/*
SystemDeleteIdentifierTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemDeleteIdentifierTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete identifier too many requests response has a 2xx status code
func (o *SystemDeleteIdentifierTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete identifier too many requests response has a 3xx status code
func (o *SystemDeleteIdentifierTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete identifier too many requests response has a 4xx status code
func (o *SystemDeleteIdentifierTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete identifier too many requests response has a 5xx status code
func (o *SystemDeleteIdentifierTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete identifier too many requests response a status code equal to that given
func (o *SystemDeleteIdentifierTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemDeleteIdentifierTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteIdentifierTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/identifiers/remove][%d] systemDeleteIdentifierTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteIdentifierTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteIdentifierTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
