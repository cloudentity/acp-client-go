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

// SystemDeleteUserReader is a Reader for the SystemDeleteUser structure.
type SystemDeleteUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemDeleteUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSystemDeleteUserNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemDeleteUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemDeleteUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemDeleteUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemDeleteUserPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemDeleteUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemDeleteUserNoContent creates a SystemDeleteUserNoContent with default headers values
func NewSystemDeleteUserNoContent() *SystemDeleteUserNoContent {
	return &SystemDeleteUserNoContent{}
}

/*
SystemDeleteUserNoContent describes a response with status code 204, with default header values.

User has been deleted
*/
type SystemDeleteUserNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this system delete user no content response has a 2xx status code
func (o *SystemDeleteUserNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system delete user no content response has a 3xx status code
func (o *SystemDeleteUserNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user no content response has a 4xx status code
func (o *SystemDeleteUserNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this system delete user no content response has a 5xx status code
func (o *SystemDeleteUserNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user no content response a status code equal to that given
func (o *SystemDeleteUserNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *SystemDeleteUserNoContent) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserNoContent ", 204)
}

func (o *SystemDeleteUserNoContent) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserNoContent ", 204)
}

func (o *SystemDeleteUserNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewSystemDeleteUserUnauthorized creates a SystemDeleteUserUnauthorized with default headers values
func NewSystemDeleteUserUnauthorized() *SystemDeleteUserUnauthorized {
	return &SystemDeleteUserUnauthorized{}
}

/*
SystemDeleteUserUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemDeleteUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete user unauthorized response has a 2xx status code
func (o *SystemDeleteUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete user unauthorized response has a 3xx status code
func (o *SystemDeleteUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user unauthorized response has a 4xx status code
func (o *SystemDeleteUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete user unauthorized response has a 5xx status code
func (o *SystemDeleteUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user unauthorized response a status code equal to that given
func (o *SystemDeleteUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemDeleteUserUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteUserUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteUserForbidden creates a SystemDeleteUserForbidden with default headers values
func NewSystemDeleteUserForbidden() *SystemDeleteUserForbidden {
	return &SystemDeleteUserForbidden{}
}

/*
SystemDeleteUserForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemDeleteUserForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete user forbidden response has a 2xx status code
func (o *SystemDeleteUserForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete user forbidden response has a 3xx status code
func (o *SystemDeleteUserForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user forbidden response has a 4xx status code
func (o *SystemDeleteUserForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete user forbidden response has a 5xx status code
func (o *SystemDeleteUserForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user forbidden response a status code equal to that given
func (o *SystemDeleteUserForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemDeleteUserForbidden) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteUserForbidden) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteUserNotFound creates a SystemDeleteUserNotFound with default headers values
func NewSystemDeleteUserNotFound() *SystemDeleteUserNotFound {
	return &SystemDeleteUserNotFound{}
}

/*
SystemDeleteUserNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemDeleteUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete user not found response has a 2xx status code
func (o *SystemDeleteUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete user not found response has a 3xx status code
func (o *SystemDeleteUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user not found response has a 4xx status code
func (o *SystemDeleteUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete user not found response has a 5xx status code
func (o *SystemDeleteUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user not found response a status code equal to that given
func (o *SystemDeleteUserNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemDeleteUserNotFound) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteUserNotFound) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteUserPreconditionFailed creates a SystemDeleteUserPreconditionFailed with default headers values
func NewSystemDeleteUserPreconditionFailed() *SystemDeleteUserPreconditionFailed {
	return &SystemDeleteUserPreconditionFailed{}
}

/*
SystemDeleteUserPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type SystemDeleteUserPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete user precondition failed response has a 2xx status code
func (o *SystemDeleteUserPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete user precondition failed response has a 3xx status code
func (o *SystemDeleteUserPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user precondition failed response has a 4xx status code
func (o *SystemDeleteUserPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete user precondition failed response has a 5xx status code
func (o *SystemDeleteUserPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user precondition failed response a status code equal to that given
func (o *SystemDeleteUserPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemDeleteUserPreconditionFailed) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteUserPreconditionFailed) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteUserPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteUserPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteUserTooManyRequests creates a SystemDeleteUserTooManyRequests with default headers values
func NewSystemDeleteUserTooManyRequests() *SystemDeleteUserTooManyRequests {
	return &SystemDeleteUserTooManyRequests{}
}

/*
SystemDeleteUserTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemDeleteUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete user too many requests response has a 2xx status code
func (o *SystemDeleteUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete user too many requests response has a 3xx status code
func (o *SystemDeleteUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete user too many requests response has a 4xx status code
func (o *SystemDeleteUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete user too many requests response has a 5xx status code
func (o *SystemDeleteUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete user too many requests response a status code equal to that given
func (o *SystemDeleteUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemDeleteUserTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteUserTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}/users/{userID}][%d] systemDeleteUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
