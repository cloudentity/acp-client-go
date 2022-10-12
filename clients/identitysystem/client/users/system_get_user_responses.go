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

// SystemGetUserReader is a Reader for the SystemGetUser structure.
type SystemGetUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemGetUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemGetUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemGetUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemGetUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemGetUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemGetUserPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemGetUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemGetUserOK creates a SystemGetUserOK with default headers values
func NewSystemGetUserOK() *SystemGetUserOK {
	return &SystemGetUserOK{}
}

/*
SystemGetUserOK describes a response with status code 200, with default header values.

User
*/
type SystemGetUserOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserWithData
}

// IsSuccess returns true when this system get user o k response has a 2xx status code
func (o *SystemGetUserOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system get user o k response has a 3xx status code
func (o *SystemGetUserOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user o k response has a 4xx status code
func (o *SystemGetUserOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system get user o k response has a 5xx status code
func (o *SystemGetUserOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user o k response a status code equal to that given
func (o *SystemGetUserOK) IsCode(code int) bool {
	return code == 200
}

func (o *SystemGetUserOK) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserOK  %+v", 200, o.Payload)
}

func (o *SystemGetUserOK) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserOK  %+v", 200, o.Payload)
}

func (o *SystemGetUserOK) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *SystemGetUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserUnauthorized creates a SystemGetUserUnauthorized with default headers values
func NewSystemGetUserUnauthorized() *SystemGetUserUnauthorized {
	return &SystemGetUserUnauthorized{}
}

/*
SystemGetUserUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SystemGetUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get user unauthorized response has a 2xx status code
func (o *SystemGetUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get user unauthorized response has a 3xx status code
func (o *SystemGetUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user unauthorized response has a 4xx status code
func (o *SystemGetUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get user unauthorized response has a 5xx status code
func (o *SystemGetUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user unauthorized response a status code equal to that given
func (o *SystemGetUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemGetUserUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetUserUnauthorized) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserForbidden creates a SystemGetUserForbidden with default headers values
func NewSystemGetUserForbidden() *SystemGetUserForbidden {
	return &SystemGetUserForbidden{}
}

/*
SystemGetUserForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SystemGetUserForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get user forbidden response has a 2xx status code
func (o *SystemGetUserForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get user forbidden response has a 3xx status code
func (o *SystemGetUserForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user forbidden response has a 4xx status code
func (o *SystemGetUserForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get user forbidden response has a 5xx status code
func (o *SystemGetUserForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user forbidden response a status code equal to that given
func (o *SystemGetUserForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemGetUserForbidden) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetUserForbidden) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserNotFound creates a SystemGetUserNotFound with default headers values
func NewSystemGetUserNotFound() *SystemGetUserNotFound {
	return &SystemGetUserNotFound{}
}

/*
SystemGetUserNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SystemGetUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get user not found response has a 2xx status code
func (o *SystemGetUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get user not found response has a 3xx status code
func (o *SystemGetUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user not found response has a 4xx status code
func (o *SystemGetUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get user not found response has a 5xx status code
func (o *SystemGetUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user not found response a status code equal to that given
func (o *SystemGetUserNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemGetUserNotFound) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetUserNotFound) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserPreconditionFailed creates a SystemGetUserPreconditionFailed with default headers values
func NewSystemGetUserPreconditionFailed() *SystemGetUserPreconditionFailed {
	return &SystemGetUserPreconditionFailed{}
}

/*
SystemGetUserPreconditionFailed describes a response with status code 412, with default header values.

HttpError
*/
type SystemGetUserPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get user precondition failed response has a 2xx status code
func (o *SystemGetUserPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get user precondition failed response has a 3xx status code
func (o *SystemGetUserPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user precondition failed response has a 4xx status code
func (o *SystemGetUserPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get user precondition failed response has a 5xx status code
func (o *SystemGetUserPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user precondition failed response a status code equal to that given
func (o *SystemGetUserPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemGetUserPreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemGetUserPreconditionFailed) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemGetUserPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserTooManyRequests creates a SystemGetUserTooManyRequests with default headers values
func NewSystemGetUserTooManyRequests() *SystemGetUserTooManyRequests {
	return &SystemGetUserTooManyRequests{}
}

/*
SystemGetUserTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SystemGetUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get user too many requests response has a 2xx status code
func (o *SystemGetUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get user too many requests response has a 3xx status code
func (o *SystemGetUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get user too many requests response has a 4xx status code
func (o *SystemGetUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get user too many requests response has a 5xx status code
func (o *SystemGetUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system get user too many requests response a status code equal to that given
func (o *SystemGetUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemGetUserTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetUserTooManyRequests) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
