// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// CreateUserReader is a Reader for the CreateUser structure.
type CreateUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateUserCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateUserConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users] createUser", response, response.Code())
	}
}

// NewCreateUserCreated creates a CreateUserCreated with default headers values
func NewCreateUserCreated() *CreateUserCreated {
	return &CreateUserCreated{}
}

/*
CreateUserCreated describes a response with status code 201, with default header values.

User
*/
type CreateUserCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserWithData
}

// IsSuccess returns true when this create user created response has a 2xx status code
func (o *CreateUserCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create user created response has a 3xx status code
func (o *CreateUserCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user created response has a 4xx status code
func (o *CreateUserCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create user created response has a 5xx status code
func (o *CreateUserCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create user created response a status code equal to that given
func (o *CreateUserCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create user created response
func (o *CreateUserCreated) Code() int {
	return 201
}

func (o *CreateUserCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserCreated %s", 201, payload)
}

func (o *CreateUserCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserCreated %s", 201, payload)
}

func (o *CreateUserCreated) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *CreateUserCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateUserBadRequest creates a CreateUserBadRequest with default headers values
func NewCreateUserBadRequest() *CreateUserBadRequest {
	return &CreateUserBadRequest{}
}

/*
CreateUserBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateUserBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user bad request response has a 2xx status code
func (o *CreateUserBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user bad request response has a 3xx status code
func (o *CreateUserBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user bad request response has a 4xx status code
func (o *CreateUserBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user bad request response has a 5xx status code
func (o *CreateUserBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create user bad request response a status code equal to that given
func (o *CreateUserBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create user bad request response
func (o *CreateUserBadRequest) Code() int {
	return 400
}

func (o *CreateUserBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserBadRequest %s", 400, payload)
}

func (o *CreateUserBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserBadRequest %s", 400, payload)
}

func (o *CreateUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserUnauthorized creates a CreateUserUnauthorized with default headers values
func NewCreateUserUnauthorized() *CreateUserUnauthorized {
	return &CreateUserUnauthorized{}
}

/*
CreateUserUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user unauthorized response has a 2xx status code
func (o *CreateUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user unauthorized response has a 3xx status code
func (o *CreateUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user unauthorized response has a 4xx status code
func (o *CreateUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user unauthorized response has a 5xx status code
func (o *CreateUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create user unauthorized response a status code equal to that given
func (o *CreateUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create user unauthorized response
func (o *CreateUserUnauthorized) Code() int {
	return 401
}

func (o *CreateUserUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnauthorized %s", 401, payload)
}

func (o *CreateUserUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnauthorized %s", 401, payload)
}

func (o *CreateUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserForbidden creates a CreateUserForbidden with default headers values
func NewCreateUserForbidden() *CreateUserForbidden {
	return &CreateUserForbidden{}
}

/*
CreateUserForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateUserForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user forbidden response has a 2xx status code
func (o *CreateUserForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user forbidden response has a 3xx status code
func (o *CreateUserForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user forbidden response has a 4xx status code
func (o *CreateUserForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user forbidden response has a 5xx status code
func (o *CreateUserForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create user forbidden response a status code equal to that given
func (o *CreateUserForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create user forbidden response
func (o *CreateUserForbidden) Code() int {
	return 403
}

func (o *CreateUserForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserForbidden %s", 403, payload)
}

func (o *CreateUserForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserForbidden %s", 403, payload)
}

func (o *CreateUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserNotFound creates a CreateUserNotFound with default headers values
func NewCreateUserNotFound() *CreateUserNotFound {
	return &CreateUserNotFound{}
}

/*
CreateUserNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user not found response has a 2xx status code
func (o *CreateUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user not found response has a 3xx status code
func (o *CreateUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user not found response has a 4xx status code
func (o *CreateUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user not found response has a 5xx status code
func (o *CreateUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create user not found response a status code equal to that given
func (o *CreateUserNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create user not found response
func (o *CreateUserNotFound) Code() int {
	return 404
}

func (o *CreateUserNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserNotFound %s", 404, payload)
}

func (o *CreateUserNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserNotFound %s", 404, payload)
}

func (o *CreateUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserConflict creates a CreateUserConflict with default headers values
func NewCreateUserConflict() *CreateUserConflict {
	return &CreateUserConflict{}
}

/*
CreateUserConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreateUserConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user conflict response has a 2xx status code
func (o *CreateUserConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user conflict response has a 3xx status code
func (o *CreateUserConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user conflict response has a 4xx status code
func (o *CreateUserConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user conflict response has a 5xx status code
func (o *CreateUserConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create user conflict response a status code equal to that given
func (o *CreateUserConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the create user conflict response
func (o *CreateUserConflict) Code() int {
	return 409
}

func (o *CreateUserConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserConflict %s", 409, payload)
}

func (o *CreateUserConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserConflict %s", 409, payload)
}

func (o *CreateUserConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserUnprocessableEntity creates a CreateUserUnprocessableEntity with default headers values
func NewCreateUserUnprocessableEntity() *CreateUserUnprocessableEntity {
	return &CreateUserUnprocessableEntity{}
}

/*
CreateUserUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateUserUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user unprocessable entity response has a 2xx status code
func (o *CreateUserUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user unprocessable entity response has a 3xx status code
func (o *CreateUserUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user unprocessable entity response has a 4xx status code
func (o *CreateUserUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user unprocessable entity response has a 5xx status code
func (o *CreateUserUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create user unprocessable entity response a status code equal to that given
func (o *CreateUserUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create user unprocessable entity response
func (o *CreateUserUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateUserUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnprocessableEntity %s", 422, payload)
}

func (o *CreateUserUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnprocessableEntity %s", 422, payload)
}

func (o *CreateUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserTooManyRequests creates a CreateUserTooManyRequests with default headers values
func NewCreateUserTooManyRequests() *CreateUserTooManyRequests {
	return &CreateUserTooManyRequests{}
}

/*
CreateUserTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create user too many requests response has a 2xx status code
func (o *CreateUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create user too many requests response has a 3xx status code
func (o *CreateUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create user too many requests response has a 4xx status code
func (o *CreateUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create user too many requests response has a 5xx status code
func (o *CreateUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create user too many requests response a status code equal to that given
func (o *CreateUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create user too many requests response
func (o *CreateUserTooManyRequests) Code() int {
	return 429
}

func (o *CreateUserTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserTooManyRequests %s", 429, payload)
}

func (o *CreateUserTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserTooManyRequests %s", 429, payload)
}

func (o *CreateUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
