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

// DeleteUserIdentifierReader is a Reader for the DeleteUserIdentifier structure.
type DeleteUserIdentifierReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteUserIdentifierReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteUserIdentifierNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteUserIdentifierUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteUserIdentifierForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteUserIdentifierNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteUserIdentifierTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteUserIdentifierNoContent creates a DeleteUserIdentifierNoContent with default headers values
func NewDeleteUserIdentifierNoContent() *DeleteUserIdentifierNoContent {
	return &DeleteUserIdentifierNoContent{}
}

/*
DeleteUserIdentifierNoContent describes a response with status code 204, with default header values.

	Identifier has been deleted
*/
type DeleteUserIdentifierNoContent struct {
}

// IsSuccess returns true when this delete user identifier no content response has a 2xx status code
func (o *DeleteUserIdentifierNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete user identifier no content response has a 3xx status code
func (o *DeleteUserIdentifierNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user identifier no content response has a 4xx status code
func (o *DeleteUserIdentifierNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete user identifier no content response has a 5xx status code
func (o *DeleteUserIdentifierNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user identifier no content response a status code equal to that given
func (o *DeleteUserIdentifierNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *DeleteUserIdentifierNoContent) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierNoContent ", 204)
}

func (o *DeleteUserIdentifierNoContent) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierNoContent ", 204)
}

func (o *DeleteUserIdentifierNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteUserIdentifierUnauthorized creates a DeleteUserIdentifierUnauthorized with default headers values
func NewDeleteUserIdentifierUnauthorized() *DeleteUserIdentifierUnauthorized {
	return &DeleteUserIdentifierUnauthorized{}
}

/*
DeleteUserIdentifierUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteUserIdentifierUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user identifier unauthorized response has a 2xx status code
func (o *DeleteUserIdentifierUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user identifier unauthorized response has a 3xx status code
func (o *DeleteUserIdentifierUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user identifier unauthorized response has a 4xx status code
func (o *DeleteUserIdentifierUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user identifier unauthorized response has a 5xx status code
func (o *DeleteUserIdentifierUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user identifier unauthorized response a status code equal to that given
func (o *DeleteUserIdentifierUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *DeleteUserIdentifierUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserIdentifierUnauthorized) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserIdentifierUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserIdentifierUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserIdentifierForbidden creates a DeleteUserIdentifierForbidden with default headers values
func NewDeleteUserIdentifierForbidden() *DeleteUserIdentifierForbidden {
	return &DeleteUserIdentifierForbidden{}
}

/*
DeleteUserIdentifierForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteUserIdentifierForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user identifier forbidden response has a 2xx status code
func (o *DeleteUserIdentifierForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user identifier forbidden response has a 3xx status code
func (o *DeleteUserIdentifierForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user identifier forbidden response has a 4xx status code
func (o *DeleteUserIdentifierForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user identifier forbidden response has a 5xx status code
func (o *DeleteUserIdentifierForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user identifier forbidden response a status code equal to that given
func (o *DeleteUserIdentifierForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *DeleteUserIdentifierForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserIdentifierForbidden) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserIdentifierForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserIdentifierForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserIdentifierNotFound creates a DeleteUserIdentifierNotFound with default headers values
func NewDeleteUserIdentifierNotFound() *DeleteUserIdentifierNotFound {
	return &DeleteUserIdentifierNotFound{}
}

/*
DeleteUserIdentifierNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteUserIdentifierNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user identifier not found response has a 2xx status code
func (o *DeleteUserIdentifierNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user identifier not found response has a 3xx status code
func (o *DeleteUserIdentifierNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user identifier not found response has a 4xx status code
func (o *DeleteUserIdentifierNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user identifier not found response has a 5xx status code
func (o *DeleteUserIdentifierNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user identifier not found response a status code equal to that given
func (o *DeleteUserIdentifierNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *DeleteUserIdentifierNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserIdentifierNotFound) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserIdentifierNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserIdentifierNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserIdentifierTooManyRequests creates a DeleteUserIdentifierTooManyRequests with default headers values
func NewDeleteUserIdentifierTooManyRequests() *DeleteUserIdentifierTooManyRequests {
	return &DeleteUserIdentifierTooManyRequests{}
}

/*
DeleteUserIdentifierTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteUserIdentifierTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user identifier too many requests response has a 2xx status code
func (o *DeleteUserIdentifierTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user identifier too many requests response has a 3xx status code
func (o *DeleteUserIdentifierTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user identifier too many requests response has a 4xx status code
func (o *DeleteUserIdentifierTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user identifier too many requests response has a 5xx status code
func (o *DeleteUserIdentifierTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user identifier too many requests response a status code equal to that given
func (o *DeleteUserIdentifierTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *DeleteUserIdentifierTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserIdentifierTooManyRequests) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/remove][%d] deleteUserIdentifierTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserIdentifierTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserIdentifierTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}