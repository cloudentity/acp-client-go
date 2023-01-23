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

// SystemCreateUserReader is a Reader for the SystemCreateUser structure.
type SystemCreateUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemCreateUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewSystemCreateUserCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemCreateUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemCreateUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemCreateUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemCreateUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSystemCreateUserConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemCreateUserPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemCreateUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemCreateUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemCreateUserCreated creates a SystemCreateUserCreated with default headers values
func NewSystemCreateUserCreated() *SystemCreateUserCreated {
	return &SystemCreateUserCreated{}
}

/*
SystemCreateUserCreated describes a response with status code 201, with default header values.

User
*/
type SystemCreateUserCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserWithData
}

// IsSuccess returns true when this system create user created response has a 2xx status code
func (o *SystemCreateUserCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system create user created response has a 3xx status code
func (o *SystemCreateUserCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user created response has a 4xx status code
func (o *SystemCreateUserCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this system create user created response has a 5xx status code
func (o *SystemCreateUserCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user created response a status code equal to that given
func (o *SystemCreateUserCreated) IsCode(code int) bool {
	return code == 201
}

func (o *SystemCreateUserCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserCreated  %+v", 201, o.Payload)
}

func (o *SystemCreateUserCreated) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserCreated  %+v", 201, o.Payload)
}

func (o *SystemCreateUserCreated) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *SystemCreateUserCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSystemCreateUserBadRequest creates a SystemCreateUserBadRequest with default headers values
func NewSystemCreateUserBadRequest() *SystemCreateUserBadRequest {
	return &SystemCreateUserBadRequest{}
}

/*
SystemCreateUserBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SystemCreateUserBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user bad request response has a 2xx status code
func (o *SystemCreateUserBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user bad request response has a 3xx status code
func (o *SystemCreateUserBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user bad request response has a 4xx status code
func (o *SystemCreateUserBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user bad request response has a 5xx status code
func (o *SystemCreateUserBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user bad request response a status code equal to that given
func (o *SystemCreateUserBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *SystemCreateUserBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserBadRequest  %+v", 400, o.Payload)
}

func (o *SystemCreateUserBadRequest) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserBadRequest  %+v", 400, o.Payload)
}

func (o *SystemCreateUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserUnauthorized creates a SystemCreateUserUnauthorized with default headers values
func NewSystemCreateUserUnauthorized() *SystemCreateUserUnauthorized {
	return &SystemCreateUserUnauthorized{}
}

/*
SystemCreateUserUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemCreateUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user unauthorized response has a 2xx status code
func (o *SystemCreateUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user unauthorized response has a 3xx status code
func (o *SystemCreateUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user unauthorized response has a 4xx status code
func (o *SystemCreateUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user unauthorized response has a 5xx status code
func (o *SystemCreateUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user unauthorized response a status code equal to that given
func (o *SystemCreateUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemCreateUserUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemCreateUserUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemCreateUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserForbidden creates a SystemCreateUserForbidden with default headers values
func NewSystemCreateUserForbidden() *SystemCreateUserForbidden {
	return &SystemCreateUserForbidden{}
}

/*
SystemCreateUserForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemCreateUserForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user forbidden response has a 2xx status code
func (o *SystemCreateUserForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user forbidden response has a 3xx status code
func (o *SystemCreateUserForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user forbidden response has a 4xx status code
func (o *SystemCreateUserForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user forbidden response has a 5xx status code
func (o *SystemCreateUserForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user forbidden response a status code equal to that given
func (o *SystemCreateUserForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemCreateUserForbidden) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemCreateUserForbidden) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserForbidden  %+v", 403, o.Payload)
}

func (o *SystemCreateUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserNotFound creates a SystemCreateUserNotFound with default headers values
func NewSystemCreateUserNotFound() *SystemCreateUserNotFound {
	return &SystemCreateUserNotFound{}
}

/*
SystemCreateUserNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemCreateUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user not found response has a 2xx status code
func (o *SystemCreateUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user not found response has a 3xx status code
func (o *SystemCreateUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user not found response has a 4xx status code
func (o *SystemCreateUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user not found response has a 5xx status code
func (o *SystemCreateUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user not found response a status code equal to that given
func (o *SystemCreateUserNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemCreateUserNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemCreateUserNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserNotFound  %+v", 404, o.Payload)
}

func (o *SystemCreateUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserConflict creates a SystemCreateUserConflict with default headers values
func NewSystemCreateUserConflict() *SystemCreateUserConflict {
	return &SystemCreateUserConflict{}
}

/*
SystemCreateUserConflict describes a response with status code 409, with default header values.

Conflict
*/
type SystemCreateUserConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user conflict response has a 2xx status code
func (o *SystemCreateUserConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user conflict response has a 3xx status code
func (o *SystemCreateUserConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user conflict response has a 4xx status code
func (o *SystemCreateUserConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user conflict response has a 5xx status code
func (o *SystemCreateUserConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user conflict response a status code equal to that given
func (o *SystemCreateUserConflict) IsCode(code int) bool {
	return code == 409
}

func (o *SystemCreateUserConflict) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserConflict  %+v", 409, o.Payload)
}

func (o *SystemCreateUserConflict) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserConflict  %+v", 409, o.Payload)
}

func (o *SystemCreateUserConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserPreconditionFailed creates a SystemCreateUserPreconditionFailed with default headers values
func NewSystemCreateUserPreconditionFailed() *SystemCreateUserPreconditionFailed {
	return &SystemCreateUserPreconditionFailed{}
}

/*
SystemCreateUserPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type SystemCreateUserPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user precondition failed response has a 2xx status code
func (o *SystemCreateUserPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user precondition failed response has a 3xx status code
func (o *SystemCreateUserPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user precondition failed response has a 4xx status code
func (o *SystemCreateUserPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user precondition failed response has a 5xx status code
func (o *SystemCreateUserPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user precondition failed response a status code equal to that given
func (o *SystemCreateUserPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemCreateUserPreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemCreateUserPreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemCreateUserPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserUnprocessableEntity creates a SystemCreateUserUnprocessableEntity with default headers values
func NewSystemCreateUserUnprocessableEntity() *SystemCreateUserUnprocessableEntity {
	return &SystemCreateUserUnprocessableEntity{}
}

/*
SystemCreateUserUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SystemCreateUserUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user unprocessable entity response has a 2xx status code
func (o *SystemCreateUserUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user unprocessable entity response has a 3xx status code
func (o *SystemCreateUserUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user unprocessable entity response has a 4xx status code
func (o *SystemCreateUserUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user unprocessable entity response has a 5xx status code
func (o *SystemCreateUserUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user unprocessable entity response a status code equal to that given
func (o *SystemCreateUserUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *SystemCreateUserUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemCreateUserUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemCreateUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreateUserTooManyRequests creates a SystemCreateUserTooManyRequests with default headers values
func NewSystemCreateUserTooManyRequests() *SystemCreateUserTooManyRequests {
	return &SystemCreateUserTooManyRequests{}
}

/*
SystemCreateUserTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemCreateUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create user too many requests response has a 2xx status code
func (o *SystemCreateUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create user too many requests response has a 3xx status code
func (o *SystemCreateUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create user too many requests response has a 4xx status code
func (o *SystemCreateUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create user too many requests response has a 5xx status code
func (o *SystemCreateUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system create user too many requests response a status code equal to that given
func (o *SystemCreateUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemCreateUserTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemCreateUserTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users][%d] systemCreateUserTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemCreateUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreateUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
