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

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// GenerateCodeForUserReader is a Reader for the GenerateCodeForUser structure.
type GenerateCodeForUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GenerateCodeForUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewGenerateCodeForUserCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGenerateCodeForUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGenerateCodeForUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGenerateCodeForUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGenerateCodeForUserPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGenerateCodeForUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGenerateCodeForUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/user/code/generate] generateCodeForUser", response, response.Code())
	}
}

// NewGenerateCodeForUserCreated creates a GenerateCodeForUserCreated with default headers values
func NewGenerateCodeForUserCreated() *GenerateCodeForUserCreated {
	return &GenerateCodeForUserCreated{}
}

/*
GenerateCodeForUserCreated describes a response with status code 201, with default header values.

Code
*/
type GenerateCodeForUserCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Codes
}

// IsSuccess returns true when this generate code for user created response has a 2xx status code
func (o *GenerateCodeForUserCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this generate code for user created response has a 3xx status code
func (o *GenerateCodeForUserCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user created response has a 4xx status code
func (o *GenerateCodeForUserCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this generate code for user created response has a 5xx status code
func (o *GenerateCodeForUserCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user created response a status code equal to that given
func (o *GenerateCodeForUserCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the generate code for user created response
func (o *GenerateCodeForUserCreated) Code() int {
	return 201
}

func (o *GenerateCodeForUserCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserCreated %s", 201, payload)
}

func (o *GenerateCodeForUserCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserCreated %s", 201, payload)
}

func (o *GenerateCodeForUserCreated) GetPayload() *models.Codes {
	return o.Payload
}

func (o *GenerateCodeForUserCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Codes)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserBadRequest creates a GenerateCodeForUserBadRequest with default headers values
func NewGenerateCodeForUserBadRequest() *GenerateCodeForUserBadRequest {
	return &GenerateCodeForUserBadRequest{}
}

/*
GenerateCodeForUserBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GenerateCodeForUserBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user bad request response has a 2xx status code
func (o *GenerateCodeForUserBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user bad request response has a 3xx status code
func (o *GenerateCodeForUserBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user bad request response has a 4xx status code
func (o *GenerateCodeForUserBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user bad request response has a 5xx status code
func (o *GenerateCodeForUserBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user bad request response a status code equal to that given
func (o *GenerateCodeForUserBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the generate code for user bad request response
func (o *GenerateCodeForUserBadRequest) Code() int {
	return 400
}

func (o *GenerateCodeForUserBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserBadRequest %s", 400, payload)
}

func (o *GenerateCodeForUserBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserBadRequest %s", 400, payload)
}

func (o *GenerateCodeForUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserUnauthorized creates a GenerateCodeForUserUnauthorized with default headers values
func NewGenerateCodeForUserUnauthorized() *GenerateCodeForUserUnauthorized {
	return &GenerateCodeForUserUnauthorized{}
}

/*
GenerateCodeForUserUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GenerateCodeForUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user unauthorized response has a 2xx status code
func (o *GenerateCodeForUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user unauthorized response has a 3xx status code
func (o *GenerateCodeForUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user unauthorized response has a 4xx status code
func (o *GenerateCodeForUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user unauthorized response has a 5xx status code
func (o *GenerateCodeForUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user unauthorized response a status code equal to that given
func (o *GenerateCodeForUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the generate code for user unauthorized response
func (o *GenerateCodeForUserUnauthorized) Code() int {
	return 401
}

func (o *GenerateCodeForUserUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserUnauthorized %s", 401, payload)
}

func (o *GenerateCodeForUserUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserUnauthorized %s", 401, payload)
}

func (o *GenerateCodeForUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserNotFound creates a GenerateCodeForUserNotFound with default headers values
func NewGenerateCodeForUserNotFound() *GenerateCodeForUserNotFound {
	return &GenerateCodeForUserNotFound{}
}

/*
GenerateCodeForUserNotFound describes a response with status code 404, with default header values.

Not found
*/
type GenerateCodeForUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user not found response has a 2xx status code
func (o *GenerateCodeForUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user not found response has a 3xx status code
func (o *GenerateCodeForUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user not found response has a 4xx status code
func (o *GenerateCodeForUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user not found response has a 5xx status code
func (o *GenerateCodeForUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user not found response a status code equal to that given
func (o *GenerateCodeForUserNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the generate code for user not found response
func (o *GenerateCodeForUserNotFound) Code() int {
	return 404
}

func (o *GenerateCodeForUserNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserNotFound %s", 404, payload)
}

func (o *GenerateCodeForUserNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserNotFound %s", 404, payload)
}

func (o *GenerateCodeForUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserPreconditionFailed creates a GenerateCodeForUserPreconditionFailed with default headers values
func NewGenerateCodeForUserPreconditionFailed() *GenerateCodeForUserPreconditionFailed {
	return &GenerateCodeForUserPreconditionFailed{}
}

/*
GenerateCodeForUserPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type GenerateCodeForUserPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user precondition failed response has a 2xx status code
func (o *GenerateCodeForUserPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user precondition failed response has a 3xx status code
func (o *GenerateCodeForUserPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user precondition failed response has a 4xx status code
func (o *GenerateCodeForUserPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user precondition failed response has a 5xx status code
func (o *GenerateCodeForUserPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user precondition failed response a status code equal to that given
func (o *GenerateCodeForUserPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the generate code for user precondition failed response
func (o *GenerateCodeForUserPreconditionFailed) Code() int {
	return 412
}

func (o *GenerateCodeForUserPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserPreconditionFailed %s", 412, payload)
}

func (o *GenerateCodeForUserPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserPreconditionFailed %s", 412, payload)
}

func (o *GenerateCodeForUserPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserUnprocessableEntity creates a GenerateCodeForUserUnprocessableEntity with default headers values
func NewGenerateCodeForUserUnprocessableEntity() *GenerateCodeForUserUnprocessableEntity {
	return &GenerateCodeForUserUnprocessableEntity{}
}

/*
GenerateCodeForUserUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type GenerateCodeForUserUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user unprocessable entity response has a 2xx status code
func (o *GenerateCodeForUserUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user unprocessable entity response has a 3xx status code
func (o *GenerateCodeForUserUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user unprocessable entity response has a 4xx status code
func (o *GenerateCodeForUserUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user unprocessable entity response has a 5xx status code
func (o *GenerateCodeForUserUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user unprocessable entity response a status code equal to that given
func (o *GenerateCodeForUserUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the generate code for user unprocessable entity response
func (o *GenerateCodeForUserUnprocessableEntity) Code() int {
	return 422
}

func (o *GenerateCodeForUserUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserUnprocessableEntity %s", 422, payload)
}

func (o *GenerateCodeForUserUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserUnprocessableEntity %s", 422, payload)
}

func (o *GenerateCodeForUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeForUserTooManyRequests creates a GenerateCodeForUserTooManyRequests with default headers values
func NewGenerateCodeForUserTooManyRequests() *GenerateCodeForUserTooManyRequests {
	return &GenerateCodeForUserTooManyRequests{}
}

/*
GenerateCodeForUserTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GenerateCodeForUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code for user too many requests response has a 2xx status code
func (o *GenerateCodeForUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code for user too many requests response has a 3xx status code
func (o *GenerateCodeForUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code for user too many requests response has a 4xx status code
func (o *GenerateCodeForUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code for user too many requests response has a 5xx status code
func (o *GenerateCodeForUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code for user too many requests response a status code equal to that given
func (o *GenerateCodeForUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the generate code for user too many requests response
func (o *GenerateCodeForUserTooManyRequests) Code() int {
	return 429
}

func (o *GenerateCodeForUserTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserTooManyRequests %s", 429, payload)
}

func (o *GenerateCodeForUserTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/code/generate][%d] generateCodeForUserTooManyRequests %s", 429, payload)
}

func (o *GenerateCodeForUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeForUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
