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

// SystemListUsersReader is a Reader for the SystemListUsers structure.
type SystemListUsersReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemListUsersReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemListUsersOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemListUsersBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemListUsersUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemListUsersForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemListUsersNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemListUsersUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemListUsersTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemListUsersOK creates a SystemListUsersOK with default headers values
func NewSystemListUsersOK() *SystemListUsersOK {
	return &SystemListUsersOK{}
}

/*
SystemListUsersOK describes a response with status code 200, with default header values.

Identity Users
*/
type SystemListUsersOK struct {
	Payload *models.Users
}

// IsSuccess returns true when this system list users o k response has a 2xx status code
func (o *SystemListUsersOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system list users o k response has a 3xx status code
func (o *SystemListUsersOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users o k response has a 4xx status code
func (o *SystemListUsersOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system list users o k response has a 5xx status code
func (o *SystemListUsersOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users o k response a status code equal to that given
func (o *SystemListUsersOK) IsCode(code int) bool {
	return code == 200
}

func (o *SystemListUsersOK) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersOK  %+v", 200, o.Payload)
}

func (o *SystemListUsersOK) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersOK  %+v", 200, o.Payload)
}

func (o *SystemListUsersOK) GetPayload() *models.Users {
	return o.Payload
}

func (o *SystemListUsersOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Users)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersBadRequest creates a SystemListUsersBadRequest with default headers values
func NewSystemListUsersBadRequest() *SystemListUsersBadRequest {
	return &SystemListUsersBadRequest{}
}

/*
SystemListUsersBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SystemListUsersBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users bad request response has a 2xx status code
func (o *SystemListUsersBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users bad request response has a 3xx status code
func (o *SystemListUsersBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users bad request response has a 4xx status code
func (o *SystemListUsersBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users bad request response has a 5xx status code
func (o *SystemListUsersBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users bad request response a status code equal to that given
func (o *SystemListUsersBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *SystemListUsersBadRequest) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersBadRequest  %+v", 400, o.Payload)
}

func (o *SystemListUsersBadRequest) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersBadRequest  %+v", 400, o.Payload)
}

func (o *SystemListUsersBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersUnauthorized creates a SystemListUsersUnauthorized with default headers values
func NewSystemListUsersUnauthorized() *SystemListUsersUnauthorized {
	return &SystemListUsersUnauthorized{}
}

/*
SystemListUsersUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemListUsersUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users unauthorized response has a 2xx status code
func (o *SystemListUsersUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users unauthorized response has a 3xx status code
func (o *SystemListUsersUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users unauthorized response has a 4xx status code
func (o *SystemListUsersUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users unauthorized response has a 5xx status code
func (o *SystemListUsersUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users unauthorized response a status code equal to that given
func (o *SystemListUsersUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemListUsersUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemListUsersUnauthorized) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemListUsersUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersForbidden creates a SystemListUsersForbidden with default headers values
func NewSystemListUsersForbidden() *SystemListUsersForbidden {
	return &SystemListUsersForbidden{}
}

/*
SystemListUsersForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemListUsersForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users forbidden response has a 2xx status code
func (o *SystemListUsersForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users forbidden response has a 3xx status code
func (o *SystemListUsersForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users forbidden response has a 4xx status code
func (o *SystemListUsersForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users forbidden response has a 5xx status code
func (o *SystemListUsersForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users forbidden response a status code equal to that given
func (o *SystemListUsersForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemListUsersForbidden) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersForbidden  %+v", 403, o.Payload)
}

func (o *SystemListUsersForbidden) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersForbidden  %+v", 403, o.Payload)
}

func (o *SystemListUsersForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersNotFound creates a SystemListUsersNotFound with default headers values
func NewSystemListUsersNotFound() *SystemListUsersNotFound {
	return &SystemListUsersNotFound{}
}

/*
SystemListUsersNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemListUsersNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users not found response has a 2xx status code
func (o *SystemListUsersNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users not found response has a 3xx status code
func (o *SystemListUsersNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users not found response has a 4xx status code
func (o *SystemListUsersNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users not found response has a 5xx status code
func (o *SystemListUsersNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users not found response a status code equal to that given
func (o *SystemListUsersNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemListUsersNotFound) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersNotFound  %+v", 404, o.Payload)
}

func (o *SystemListUsersNotFound) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersNotFound  %+v", 404, o.Payload)
}

func (o *SystemListUsersNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersUnprocessableEntity creates a SystemListUsersUnprocessableEntity with default headers values
func NewSystemListUsersUnprocessableEntity() *SystemListUsersUnprocessableEntity {
	return &SystemListUsersUnprocessableEntity{}
}

/*
SystemListUsersUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SystemListUsersUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users unprocessable entity response has a 2xx status code
func (o *SystemListUsersUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users unprocessable entity response has a 3xx status code
func (o *SystemListUsersUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users unprocessable entity response has a 4xx status code
func (o *SystemListUsersUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users unprocessable entity response has a 5xx status code
func (o *SystemListUsersUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users unprocessable entity response a status code equal to that given
func (o *SystemListUsersUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *SystemListUsersUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemListUsersUnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemListUsersUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListUsersTooManyRequests creates a SystemListUsersTooManyRequests with default headers values
func NewSystemListUsersTooManyRequests() *SystemListUsersTooManyRequests {
	return &SystemListUsersTooManyRequests{}
}

/*
SystemListUsersTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemListUsersTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list users too many requests response has a 2xx status code
func (o *SystemListUsersTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list users too many requests response has a 3xx status code
func (o *SystemListUsersTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list users too many requests response has a 4xx status code
func (o *SystemListUsersTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list users too many requests response has a 5xx status code
func (o *SystemListUsersTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system list users too many requests response a status code equal to that given
func (o *SystemListUsersTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemListUsersTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemListUsersTooManyRequests) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users][%d] systemListUsersTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemListUsersTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListUsersTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}