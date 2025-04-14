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

// DeleteUserVerifiableAddressReader is a Reader for the DeleteUserVerifiableAddress structure.
type DeleteUserVerifiableAddressReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteUserVerifiableAddressReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteUserVerifiableAddressNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteUserVerifiableAddressUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteUserVerifiableAddressForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteUserVerifiableAddressNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteUserVerifiableAddressTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove] deleteUserVerifiableAddress", response, response.Code())
	}
}

// NewDeleteUserVerifiableAddressNoContent creates a DeleteUserVerifiableAddressNoContent with default headers values
func NewDeleteUserVerifiableAddressNoContent() *DeleteUserVerifiableAddressNoContent {
	return &DeleteUserVerifiableAddressNoContent{}
}

/*
DeleteUserVerifiableAddressNoContent describes a response with status code 204, with default header values.

	Address Deleted
*/
type DeleteUserVerifiableAddressNoContent struct {
}

// IsSuccess returns true when this delete user verifiable address no content response has a 2xx status code
func (o *DeleteUserVerifiableAddressNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete user verifiable address no content response has a 3xx status code
func (o *DeleteUserVerifiableAddressNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user verifiable address no content response has a 4xx status code
func (o *DeleteUserVerifiableAddressNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete user verifiable address no content response has a 5xx status code
func (o *DeleteUserVerifiableAddressNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user verifiable address no content response a status code equal to that given
func (o *DeleteUserVerifiableAddressNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete user verifiable address no content response
func (o *DeleteUserVerifiableAddressNoContent) Code() int {
	return 204
}

func (o *DeleteUserVerifiableAddressNoContent) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressNoContent ", 204)
}

func (o *DeleteUserVerifiableAddressNoContent) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressNoContent ", 204)
}

func (o *DeleteUserVerifiableAddressNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteUserVerifiableAddressUnauthorized creates a DeleteUserVerifiableAddressUnauthorized with default headers values
func NewDeleteUserVerifiableAddressUnauthorized() *DeleteUserVerifiableAddressUnauthorized {
	return &DeleteUserVerifiableAddressUnauthorized{}
}

/*
DeleteUserVerifiableAddressUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteUserVerifiableAddressUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user verifiable address unauthorized response has a 2xx status code
func (o *DeleteUserVerifiableAddressUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user verifiable address unauthorized response has a 3xx status code
func (o *DeleteUserVerifiableAddressUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user verifiable address unauthorized response has a 4xx status code
func (o *DeleteUserVerifiableAddressUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user verifiable address unauthorized response has a 5xx status code
func (o *DeleteUserVerifiableAddressUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user verifiable address unauthorized response a status code equal to that given
func (o *DeleteUserVerifiableAddressUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete user verifiable address unauthorized response
func (o *DeleteUserVerifiableAddressUnauthorized) Code() int {
	return 401
}

func (o *DeleteUserVerifiableAddressUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserVerifiableAddressUnauthorized) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserVerifiableAddressUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserVerifiableAddressUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserVerifiableAddressForbidden creates a DeleteUserVerifiableAddressForbidden with default headers values
func NewDeleteUserVerifiableAddressForbidden() *DeleteUserVerifiableAddressForbidden {
	return &DeleteUserVerifiableAddressForbidden{}
}

/*
DeleteUserVerifiableAddressForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteUserVerifiableAddressForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user verifiable address forbidden response has a 2xx status code
func (o *DeleteUserVerifiableAddressForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user verifiable address forbidden response has a 3xx status code
func (o *DeleteUserVerifiableAddressForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user verifiable address forbidden response has a 4xx status code
func (o *DeleteUserVerifiableAddressForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user verifiable address forbidden response has a 5xx status code
func (o *DeleteUserVerifiableAddressForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user verifiable address forbidden response a status code equal to that given
func (o *DeleteUserVerifiableAddressForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete user verifiable address forbidden response
func (o *DeleteUserVerifiableAddressForbidden) Code() int {
	return 403
}

func (o *DeleteUserVerifiableAddressForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserVerifiableAddressForbidden) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *DeleteUserVerifiableAddressForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserVerifiableAddressForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserVerifiableAddressNotFound creates a DeleteUserVerifiableAddressNotFound with default headers values
func NewDeleteUserVerifiableAddressNotFound() *DeleteUserVerifiableAddressNotFound {
	return &DeleteUserVerifiableAddressNotFound{}
}

/*
DeleteUserVerifiableAddressNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteUserVerifiableAddressNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user verifiable address not found response has a 2xx status code
func (o *DeleteUserVerifiableAddressNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user verifiable address not found response has a 3xx status code
func (o *DeleteUserVerifiableAddressNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user verifiable address not found response has a 4xx status code
func (o *DeleteUserVerifiableAddressNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user verifiable address not found response has a 5xx status code
func (o *DeleteUserVerifiableAddressNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user verifiable address not found response a status code equal to that given
func (o *DeleteUserVerifiableAddressNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete user verifiable address not found response
func (o *DeleteUserVerifiableAddressNotFound) Code() int {
	return 404
}

func (o *DeleteUserVerifiableAddressNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserVerifiableAddressNotFound) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserVerifiableAddressNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserVerifiableAddressNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserVerifiableAddressTooManyRequests creates a DeleteUserVerifiableAddressTooManyRequests with default headers values
func NewDeleteUserVerifiableAddressTooManyRequests() *DeleteUserVerifiableAddressTooManyRequests {
	return &DeleteUserVerifiableAddressTooManyRequests{}
}

/*
DeleteUserVerifiableAddressTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteUserVerifiableAddressTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete user verifiable address too many requests response has a 2xx status code
func (o *DeleteUserVerifiableAddressTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete user verifiable address too many requests response has a 3xx status code
func (o *DeleteUserVerifiableAddressTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete user verifiable address too many requests response has a 4xx status code
func (o *DeleteUserVerifiableAddressTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete user verifiable address too many requests response has a 5xx status code
func (o *DeleteUserVerifiableAddressTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete user verifiable address too many requests response a status code equal to that given
func (o *DeleteUserVerifiableAddressTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete user verifiable address too many requests response
func (o *DeleteUserVerifiableAddressTooManyRequests) Code() int {
	return 429
}

func (o *DeleteUserVerifiableAddressTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserVerifiableAddressTooManyRequests) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/remove][%d] deleteUserVerifiableAddressTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteUserVerifiableAddressTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteUserVerifiableAddressTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
