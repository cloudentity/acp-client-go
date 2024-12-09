// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// SetPasswordStateReader is a Reader for the SetPasswordState structure.
type SetPasswordStateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetPasswordStateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSetPasswordStateNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetPasswordStateBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSetPasswordStateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetPasswordStateNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetPasswordStateUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /admin/pools/{ipID}/users/{userID}/password/state] setPasswordState", response, response.Code())
	}
}

// NewSetPasswordStateNoContent creates a SetPasswordStateNoContent with default headers values
func NewSetPasswordStateNoContent() *SetPasswordStateNoContent {
	return &SetPasswordStateNoContent{}
}

/*
SetPasswordStateNoContent describes a response with status code 204, with default header values.

	State set
*/
type SetPasswordStateNoContent struct {
}

// IsSuccess returns true when this set password state no content response has a 2xx status code
func (o *SetPasswordStateNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set password state no content response has a 3xx status code
func (o *SetPasswordStateNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set password state no content response has a 4xx status code
func (o *SetPasswordStateNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this set password state no content response has a 5xx status code
func (o *SetPasswordStateNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this set password state no content response a status code equal to that given
func (o *SetPasswordStateNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the set password state no content response
func (o *SetPasswordStateNoContent) Code() int {
	return 204
}

func (o *SetPasswordStateNoContent) Error() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateNoContent ", 204)
}

func (o *SetPasswordStateNoContent) String() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateNoContent ", 204)
}

func (o *SetPasswordStateNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSetPasswordStateBadRequest creates a SetPasswordStateBadRequest with default headers values
func NewSetPasswordStateBadRequest() *SetPasswordStateBadRequest {
	return &SetPasswordStateBadRequest{}
}

/*
SetPasswordStateBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SetPasswordStateBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this set password state bad request response has a 2xx status code
func (o *SetPasswordStateBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set password state bad request response has a 3xx status code
func (o *SetPasswordStateBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set password state bad request response has a 4xx status code
func (o *SetPasswordStateBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set password state bad request response has a 5xx status code
func (o *SetPasswordStateBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set password state bad request response a status code equal to that given
func (o *SetPasswordStateBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set password state bad request response
func (o *SetPasswordStateBadRequest) Code() int {
	return 400
}

func (o *SetPasswordStateBadRequest) Error() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateBadRequest  %+v", 400, o.Payload)
}

func (o *SetPasswordStateBadRequest) String() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateBadRequest  %+v", 400, o.Payload)
}

func (o *SetPasswordStateBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetPasswordStateBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPasswordStateUnauthorized creates a SetPasswordStateUnauthorized with default headers values
func NewSetPasswordStateUnauthorized() *SetPasswordStateUnauthorized {
	return &SetPasswordStateUnauthorized{}
}

/*
SetPasswordStateUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetPasswordStateUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set password state unauthorized response has a 2xx status code
func (o *SetPasswordStateUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set password state unauthorized response has a 3xx status code
func (o *SetPasswordStateUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set password state unauthorized response has a 4xx status code
func (o *SetPasswordStateUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set password state unauthorized response has a 5xx status code
func (o *SetPasswordStateUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set password state unauthorized response a status code equal to that given
func (o *SetPasswordStateUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set password state unauthorized response
func (o *SetPasswordStateUnauthorized) Code() int {
	return 401
}

func (o *SetPasswordStateUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateUnauthorized  %+v", 401, o.Payload)
}

func (o *SetPasswordStateUnauthorized) String() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateUnauthorized  %+v", 401, o.Payload)
}

func (o *SetPasswordStateUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetPasswordStateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPasswordStateNotFound creates a SetPasswordStateNotFound with default headers values
func NewSetPasswordStateNotFound() *SetPasswordStateNotFound {
	return &SetPasswordStateNotFound{}
}

/*
SetPasswordStateNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetPasswordStateNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set password state not found response has a 2xx status code
func (o *SetPasswordStateNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set password state not found response has a 3xx status code
func (o *SetPasswordStateNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set password state not found response has a 4xx status code
func (o *SetPasswordStateNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set password state not found response has a 5xx status code
func (o *SetPasswordStateNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set password state not found response a status code equal to that given
func (o *SetPasswordStateNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set password state not found response
func (o *SetPasswordStateNotFound) Code() int {
	return 404
}

func (o *SetPasswordStateNotFound) Error() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateNotFound  %+v", 404, o.Payload)
}

func (o *SetPasswordStateNotFound) String() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateNotFound  %+v", 404, o.Payload)
}

func (o *SetPasswordStateNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetPasswordStateNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetPasswordStateUnprocessableEntity creates a SetPasswordStateUnprocessableEntity with default headers values
func NewSetPasswordStateUnprocessableEntity() *SetPasswordStateUnprocessableEntity {
	return &SetPasswordStateUnprocessableEntity{}
}

/*
SetPasswordStateUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SetPasswordStateUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this set password state unprocessable entity response has a 2xx status code
func (o *SetPasswordStateUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set password state unprocessable entity response has a 3xx status code
func (o *SetPasswordStateUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set password state unprocessable entity response has a 4xx status code
func (o *SetPasswordStateUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this set password state unprocessable entity response has a 5xx status code
func (o *SetPasswordStateUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this set password state unprocessable entity response a status code equal to that given
func (o *SetPasswordStateUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the set password state unprocessable entity response
func (o *SetPasswordStateUnprocessableEntity) Code() int {
	return 422
}

func (o *SetPasswordStateUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetPasswordStateUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /admin/pools/{ipID}/users/{userID}/password/state][%d] setPasswordStateUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetPasswordStateUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetPasswordStateUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
